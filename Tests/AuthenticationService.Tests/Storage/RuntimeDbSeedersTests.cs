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
/// <see cref="RuntimeDbSeeders"/> seeds the admin account at startup. Covers happy path,
/// already-seeded (subsequent startup), multi-replica race (duplicate-username/email treated as benign),
/// real misconfiguration, transient DB errors, and unexpected exceptions.
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
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>()).Returns(IdentityResult.Success);
        var seededUser = new User { Id = "admin-id", Email = "admin@example.com" };
        manager.FindByEmailAsync(Arg.Any<string>()).Returns(seededUser);
        manager.AddToRoleAsync(seededUser, Arg.Any<string>()).Returns(IdentityResult.Success);

        await app.SeedAdministratorAccountAsync();

        await manager.Received(1).CreateAsync(
            Arg.Is<User>(u => u.UserName == UserConstants.Admin && u.EmailConfirmed == true),
            Arg.Is<string>(p => p == "AdminPa$$1234"));
        await manager.Received(1).AddToRoleAsync(seededUser, RolesConstants.Admin);
        await manager.Received(1).AddToRoleAsync(seededUser, RolesConstants.DefaultUser);
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_AdminAlreadyExists_NoOp()
    {
        var (app, manager) = BuildApp();
        var existing = new User { Id = "admin-id" };
        manager.FindByNameAsync(UserConstants.Admin).Returns(existing);

        await app.SeedAdministratorAccountAsync();

        await manager.DidNotReceive().CreateAsync(Arg.Any<User>(), Arg.Any<string>());
        await manager.DidNotReceive().AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>());
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_DuplicateUsernameRace_TreatedAsSuccess()
    {
        // Another replica seeded the admin first between our FindByName and CreateAsync.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "DuplicateUserName", Description = "duplicate" }));

        var act = async () => await app.SeedAdministratorAccountAsync();

        await act.Should().NotThrowAsync(
            because: "another replica winning the create-admin race is the documented benign case.");
        await manager.DidNotReceive().AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>());
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_DuplicateEmailRace_TreatedAsSuccess()
    {
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "DuplicateEmail", Description = "duplicate" }));

        var act = async () => await app.SeedAdministratorAccountAsync();

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_RealConfigurationError_ThrowsArgumentExceptionWithErrors()
    {
        // Operator misconfiguration must fail startup with a useful message.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "PasswordTooShort", Description = "Password must be 12+ chars." }));

        var act = async () => await app.SeedAdministratorAccountAsync();

        (await act.Should().ThrowAsync<ArgumentException>())
            .WithMessage("*AdminAccountSeedSettings is configured incorrectly*Password must be 12+ chars*");
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_TransientDatabaseError_RethrowsForOrchestratorReschedule()
    {
        // Fail fast so K8s reschedules the pod.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns<Task<User?>>(_ => throw new TestDbException("connection refused"));

        var act = async () => await app.SeedAdministratorAccountAsync();

        await act.Should().ThrowAsync<TestDbException>();
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_UnexpectedException_Rethrows()
    {
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns<Task<User?>>(_ => throw new InvalidOperationException("kaboom"));

        var act = async () => await app.SeedAdministratorAccountAsync();

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task RuntimeDbSeedAsync_DelegatesToSeedAdministratorAccountAsync()
    {
        var (app, manager) = BuildApp();
        var existing = new User { Id = "id" };
        manager.FindByNameAsync(UserConstants.Admin).Returns(existing);

        var returned = await app.RuntimeDbSeedAsync();

        returned.Should().BeSameAs(app);
        await manager.DidNotReceive().CreateAsync(Arg.Any<User>(), Arg.Any<string>());
    }

    private (WebApplication app, UserManager<User> manager) BuildApp()
    {
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
    /// DbException is abstract — need a concrete subclass to simulate the transient-DB branch.
    /// </summary>
    private sealed class TestDbException : DbException
    {
        public TestDbException(string message) : base(message) { }
    }
}
