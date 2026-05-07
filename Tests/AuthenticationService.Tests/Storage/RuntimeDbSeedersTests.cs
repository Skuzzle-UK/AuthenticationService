using System.Data.Common;
using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Storage.Seed;
using AwesomeAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Storage;

/// <summary>
/// <para><see cref="RuntimeDbSeeders"/> runs once at startup to seed the admin account.
/// Paths covered:</para>
/// <list type="bullet">
///   <item><description>Happy path: admin not present → CreateAsync succeeds → roles attached → log emitted.</description></item>
///   <item><description>Admin already present (re-run on subsequent startups) → no-op, no exception.</description></item>
///   <item><description>Multi-replica race: another replica created the admin between our FindByName and CreateAsync → DuplicateUserName/Email error → treated as success, info-logged.</description></item>
///   <item><description>Genuine misconfiguration (e.g., password too weak): result.Failed → ArgumentException with description.</description></item>
///   <item><description>Database unreachable (DbException raised mid-seed): logged at Critical, re-thrown so the host fails fast.</description></item>
///   <item><description>Unexpected exception (non-DB): logged at Critical, re-thrown.</description></item>
/// </list>
/// </summary>
public class RuntimeDbSeedersTests : IDisposable
{
    private readonly List<SqliteConnection> _connections = new();

    public void Dispose()
    {
        foreach (var c in _connections) c.Dispose();
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_HappyPath_CreatesAdminWithBothRoles()
    {
        // arrange — fresh DB, admin doesn't exist yet.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>()).Returns(IdentityResult.Success);
        var seededUser = new User { Id = "admin-id", Email = "admin@example.com" };
        manager.FindByEmailAsync(Arg.Any<string>()).Returns(seededUser);
        manager.AddToRoleAsync(seededUser, Arg.Any<string>()).Returns(IdentityResult.Success);

        // act
        await app.SeedAdministratorAccountAsync();

        // assert
        await manager.Received(1).CreateAsync(
            Arg.Is<User>(u => u.UserName == UserConstants.Admin && u.EmailConfirmed == true),
            Arg.Is<string>(p => p == "AdminPa$$1234"));
        await manager.Received(1).AddToRoleAsync(seededUser, RolesConstants.Admin);
        await manager.Received(1).AddToRoleAsync(seededUser, RolesConstants.DefaultUser);
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_AdminAlreadyExists_NoOp()
    {
        // arrange — re-run on a subsequent startup.
        var (app, manager) = BuildApp();
        var existing = new User { Id = "admin-id" };
        manager.FindByNameAsync(UserConstants.Admin).Returns(existing);

        // act
        await app.SeedAdministratorAccountAsync();

        // assert — no creation attempted.
        await manager.DidNotReceive().CreateAsync(Arg.Any<User>(), Arg.Any<string>());
        await manager.DidNotReceive().AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>());
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_DuplicateUsernameRace_TreatedAsSuccess()
    {
        // arrange — between FindByName and CreateAsync another replica seeded the admin
        // first. CreateAsync returns Failed with DuplicateUserName. The seeder treats
        // this as benign and returns without throwing.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "DuplicateUserName", Description = "duplicate" }));

        // act
        var act = async () => await app.SeedAdministratorAccountAsync();

        // assert
        await act.Should().NotThrowAsync(
            because: "another replica winning the create-admin race is the documented benign case.");
        // Roles aren't added because we believe the other replica already did so.
        await manager.DidNotReceive().AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>());
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_DuplicateEmailRace_TreatedAsSuccess()
    {
        // arrange — same race-loss path but the duplicate code is on email rather than
        // username (e.g., admin email matches an existing seeded row from a previous run).
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "DuplicateEmail", Description = "duplicate" }));

        // act
        var act = async () => await app.SeedAdministratorAccountAsync();

        // assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_RealConfigurationError_ThrowsArgumentExceptionWithErrors()
    {
        // arrange — Identity rejected the admin password (e.g., it's too short for the
        // configured complexity rules). This is operator misconfiguration and must fail
        // startup with a useful message.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "PasswordTooShort", Description = "Password must be 12+ chars." }));

        // act
        var act = async () => await app.SeedAdministratorAccountAsync();

        // assert
        (await act.Should().ThrowAsync<ArgumentException>())
            .WithMessage("*AdminAccountSeedSettings is configured incorrectly*Password must be 12+ chars*");
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_TransientDatabaseError_RethrowsForOrchestratorReschedule()
    {
        // arrange — DB unavailable (DbException is the base type of MySqlException).
        // Service should fail fast so K8s reschedules the pod.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns<Task<User?>>(_ => throw new TestDbException("connection refused"));

        // act
        var act = async () => await app.SeedAdministratorAccountAsync();

        // assert — original exception bubbles up unchanged so the host's unhandled-
        // exception path can write it.
        await act.Should().ThrowAsync<TestDbException>();
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_UnexpectedException_Rethrows()
    {
        // arrange — non-DB unexpected error (e.g., null reference inside Identity).
        // Same fail-fast contract.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns<Task<User?>>(_ => throw new InvalidOperationException("kaboom"));

        // act
        var act = async () => await app.SeedAdministratorAccountAsync();

        // assert
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task RuntimeDbSeedAsync_DelegatesToSeedAdministratorAccountAsync()
    {
        // arrange — composite entry point. If a future seeder is added, this composes
        // them; for now it just calls the admin seeder.
        var (app, manager) = BuildApp();
        var existing = new User { Id = "id" };
        manager.FindByNameAsync(UserConstants.Admin).Returns(existing);

        // act
        var returned = await app.RuntimeDbSeedAsync();

        // assert — returns the WebApplication for chaining and didn't try to recreate.
        returned.Should().BeSameAs(app);
        await manager.DidNotReceive().CreateAsync(Arg.Any<User>(), Arg.Any<string>());
    }

    private (WebApplication app, UserManager<User> manager) BuildApp()
    {
        // arrange — a real WebApplication with a substituted UserManager so we can drive
        // the seeder's branches. SQLite InMemory keeps DatabaseContext registration valid
        // (DI wires it transitively via IdentityDbContext).
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        var manager = StubUserManager();
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddSingleton(manager);
        builder.Services.AddSingleton(Options.Create(new AdminAccountSeedSettings
        {
            Email = "admin@example.com",
            Password = "AdminPa$$1234",
            FirstName = "Admin",
        }));
        builder.Services.AddSingleton<ILoggerFactory>(_ => NullLoggerFactory.Instance);

        return (builder.Build(), manager);
    }

    private static UserManager<User> StubUserManager()
    {
        var store = Substitute.For<IUserStore<User>>();
        return Substitute.For<UserManager<User>>(store, null!, null!, null!, null!, null!, null!, null!, null!);
    }

    /// <summary>
    /// Concrete DbException so we can simulate the "DB unreachable" branch the seeder
    /// detects via its IsTransientDatabaseError walk. DbException is abstract so we need
    /// our own subclass.
    /// </summary>
    private sealed class TestDbException : DbException
    {
        public TestDbException(string message) : base(message) { }
    }
}
