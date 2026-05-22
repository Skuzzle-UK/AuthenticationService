using System.Data.Common;
using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Storage;
using AuthenticationService.Storage.Seed;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
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
        // arrange
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
        // arrange
        var (app, manager) = BuildApp();
        var existing = new User { Id = "admin-id" };
        manager.FindByNameAsync(UserConstants.Admin).Returns(existing);

        // act
        await app.SeedAdministratorAccountAsync();

        // assert
        await manager.DidNotReceive().CreateAsync(Arg.Any<User>(), Arg.Any<string>());
        await manager.DidNotReceive().AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>());
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_DuplicateUsernameRace_TreatedAsSuccess()
    {
        // arrange — another replica seeded the admin first between our FindByName and CreateAsync.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "DuplicateUserName", Description = "duplicate" }));

        // act + assert
        var act = async () => await app.SeedAdministratorAccountAsync();

        await act.Should().NotThrowAsync(
            because: "another replica winning the create-admin race is the documented benign case.");
        await manager.DidNotReceive().AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>());
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_DuplicateEmailRace_TreatedAsSuccess()
    {
        // arrange
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "DuplicateEmail", Description = "duplicate" }));

        // act + assert
        var act = async () => await app.SeedAdministratorAccountAsync();

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_RealConfigurationError_ThrowsArgumentExceptionWithErrors()
    {
        // arrange — operator misconfiguration must fail startup with a useful message.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "PasswordTooShort", Description = "Password must be 12+ chars." }));

        // act + assert
        var act = async () => await app.SeedAdministratorAccountAsync();

        (await act.Should().ThrowAsync<ArgumentException>())
            .WithMessage("*AdminAccountSeedSettings is configured incorrectly*Password must be 12+ chars*");
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_TransientDatabaseError_RethrowsForOrchestratorReschedule()
    {
        // arrange — fail fast so K8s reschedules the pod.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns<Task<User?>>(_ => throw new TestDbException("connection refused"));

        // act + assert
        var act = async () => await app.SeedAdministratorAccountAsync();

        await act.Should().ThrowAsync<TestDbException>();
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_UnexpectedException_Rethrows()
    {
        // arrange
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns<Task<User?>>(_ => throw new InvalidOperationException("kaboom"));

        // act + assert
        var act = async () => await app.SeedAdministratorAccountAsync();

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task RuntimeDbSeedAsync_DelegatesToSeedAdministratorAccountAsync()
    {
        // arrange
        var (app, manager) = BuildApp();
        var existing = new User { Id = "id" };
        manager.FindByNameAsync(UserConstants.Admin).Returns(existing);

        // act
        var returned = await app.RuntimeDbSeedAsync();

        // assert
        returned.Should().BeSameAs(app);
        await manager.DidNotReceive().CreateAsync(Arg.Any<User>(), Arg.Any<string>());
    }

    // ─── ResetAdministratorAccountAsync (CLI break-glass entry point) ───────────────────

    [Fact]
    public async Task ResetAdministratorAccountAsync_HappyPath_RunsFullResetSequence()
    {
        // arrange
        var (app, manager) = BuildApp();
        var admin = new User { Id = "admin-id", UserName = UserConstants.Admin, Email = "admin@example.com" };
        manager.FindByNameAsync(UserConstants.Admin).Returns(admin);
        manager.GeneratePasswordResetTokenAsync(admin).Returns("reset-token");
        manager.ResetPasswordAsync(admin, "reset-token", "AdminPa$$1234").Returns(IdentityResult.Success);
        manager.GetTwoFactorEnabledAsync(admin).Returns(true);
        manager.IsInRoleAsync(admin, Arg.Any<string>()).Returns(true);

        // Seed a User row (FK target) + a refresh token row that the reset should consume.
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
            db.Users.Add(admin);
            db.RefreshTokens.Add(new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = admin.Id,
                FamilyId = Guid.NewGuid(),
                TokenHash = "hash",
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(5),
            });
            await db.SaveChangesAsync();
        }

        // act
        await app.ResetAdministratorAccountAsync();

        // assert
        await manager.Received(1).SetLockoutEndDateAsync(admin, null);
        await manager.Received(1).ResetAccessFailedCountAsync(admin);
        await manager.Received(1).ResetPasswordAsync(admin, "reset-token", "AdminPa$$1234");
        await manager.Received(1).SetTwoFactorEnabledAsync(admin, false);
        await manager.Received(1).UpdateSecurityStampAsync(admin);

        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
            var token = await db.RefreshTokens.AsNoTracking().FirstAsync();
            token.ConsumedAt.Should().NotBeNull();
            token.RevocationReason.Should().Be(RevocationReasons.AdminRecovery);
        }
    }

    [Fact]
    public async Task ResetAdministratorAccountAsync_AdminMissing_NoOpAndDoesNotThrow()
    {
        // arrange — recovery is for resetting an existing admin, not for creating one.
        var (app, manager) = BuildApp();
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);

        // act
        await app.ResetAdministratorAccountAsync();

        // assert
        await manager.DidNotReceive().ResetPasswordAsync(Arg.Any<User>(), Arg.Any<string>(), Arg.Any<string>());
        await manager.DidNotReceive().SetLockoutEndDateAsync(Arg.Any<User>(), Arg.Any<DateTimeOffset?>());
    }

    [Fact]
    public async Task ResetAdministratorAccountAsync_PasswordRejectedByPolicy_Throws()
    {
        // arrange
        var (app, manager) = BuildApp();
        var admin = new User { Id = "admin-id", UserName = UserConstants.Admin };
        manager.FindByNameAsync(UserConstants.Admin).Returns(admin);
        manager.GeneratePasswordResetTokenAsync(admin).Returns("tok");
        manager.ResetPasswordAsync(admin, "tok", Arg.Any<string>()).Returns(IdentityResult.Failed(
            new IdentityError { Code = "PasswordTooShort", Description = "Password must be 12+ chars." }));

        // act + assert
        var act = async () => await app.ResetAdministratorAccountAsync();

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*PasswordTooShort*Password must be 12+ chars*");
    }

    [Fact]
    public async Task ResetAdministratorAccountAsync_ReConfirmsEmailIfNeeded()
    {
        // arrange
        var (app, manager) = BuildApp();
        var admin = new User { Id = "admin-id", UserName = UserConstants.Admin, EmailConfirmed = false };
        manager.FindByNameAsync(UserConstants.Admin).Returns(admin);
        manager.GeneratePasswordResetTokenAsync(admin).Returns("tok");
        manager.ResetPasswordAsync(admin, "tok", Arg.Any<string>()).Returns(IdentityResult.Success);
        manager.IsInRoleAsync(admin, Arg.Any<string>()).Returns(true);

        // act
        await app.ResetAdministratorAccountAsync();

        // assert
        admin.EmailConfirmed.Should().BeTrue();
        await manager.Received(1).UpdateAsync(admin);
    }

    [Fact]
    public async Task ResetAdministratorAccountAsync_ReAddsMissingRoles()
    {
        // arrange — defensive: if role membership was somehow lost (e.g. a manual DB edit), recovery restores it.
        var (app, manager) = BuildApp();
        var admin = new User { Id = "admin-id", UserName = UserConstants.Admin, EmailConfirmed = true };
        manager.FindByNameAsync(UserConstants.Admin).Returns(admin);
        manager.GeneratePasswordResetTokenAsync(admin).Returns("tok");
        manager.ResetPasswordAsync(admin, "tok", Arg.Any<string>()).Returns(IdentityResult.Success);
        manager.IsInRoleAsync(admin, RolesConstants.Admin).Returns(false);
        manager.IsInRoleAsync(admin, RolesConstants.DefaultUser).Returns(false);

        // act
        await app.ResetAdministratorAccountAsync();

        // assert
        await manager.Received(1).AddToRoleAsync(admin, RolesConstants.Admin);
        await manager.Received(1).AddToRoleAsync(admin, RolesConstants.DefaultUser);
    }

    // ─── SeedAdministratorAccountAsync — ResetOnStartup flag ──────────────────────────────

    [Fact]
    public async Task SeedAdministratorAccountAsync_ResetOnStartupTrue_TriggersResetOnExistingAdmin()
    {
        // arrange
        var (app, manager) = BuildApp(settings => settings.ResetOnStartup = true);
        var admin = new User { Id = "admin-id", UserName = UserConstants.Admin, EmailConfirmed = true };
        manager.FindByNameAsync(UserConstants.Admin).Returns(admin);
        manager.GeneratePasswordResetTokenAsync(admin).Returns("tok");
        manager.ResetPasswordAsync(admin, "tok", Arg.Any<string>()).Returns(IdentityResult.Success);
        manager.IsInRoleAsync(admin, Arg.Any<string>()).Returns(true);

        // act
        await app.SeedAdministratorAccountAsync();

        // assert
        await manager.Received(1).ResetPasswordAsync(admin, "tok", Arg.Any<string>());
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_ResetOnStartupFalse_DoesNotResetExistingAdmin()
    {
        // arrange — default (off). Existing-admin path must remain the no-op it always was.
        var (app, manager) = BuildApp();
        var admin = new User { Id = "admin-id" };
        manager.FindByNameAsync(UserConstants.Admin).Returns(admin);

        // act
        await app.SeedAdministratorAccountAsync();

        // assert
        await manager.DidNotReceive().ResetPasswordAsync(Arg.Any<User>(), Arg.Any<string>(), Arg.Any<string>());
        await manager.DidNotReceive().SetLockoutEndDateAsync(Arg.Any<User>(), Arg.Any<DateTimeOffset?>());
    }

    [Fact]
    public async Task SeedAdministratorAccountAsync_ResetOnStartupTrueButAdminMissing_FallsThroughToCreate()
    {
        // arrange — ResetOnStartup is "reset if present"; if no admin exists at all, create it.
        var (app, manager) = BuildApp(settings => settings.ResetOnStartup = true);
        manager.FindByNameAsync(UserConstants.Admin).Returns((User?)null);
        manager.CreateAsync(Arg.Any<User>(), Arg.Any<string>()).Returns(IdentityResult.Success);
        var seeded = new User { Id = "admin-id", Email = "admin@example.com" };
        manager.FindByEmailAsync(Arg.Any<string>()).Returns(seeded);
        manager.AddToRoleAsync(seeded, Arg.Any<string>()).Returns(IdentityResult.Success);

        // act
        await app.SeedAdministratorAccountAsync();

        // assert
        await manager.Received(1).CreateAsync(Arg.Any<User>(), "AdminPa$$1234");
        await manager.DidNotReceive().ResetPasswordAsync(Arg.Any<User>(), Arg.Any<string>(), Arg.Any<string>());
    }

    private (WebApplication app, UserManager<User> manager) BuildApp(
        Action<AdminAccountSeedSettings>? configure = null)
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        var manager = StubUserManager();
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddSingleton(manager);

        var settings = new AdminAccountSeedSettings
        {
            Email = "admin@example.com",
            Password = "AdminPa$$1234",
            FirstName = "Admin",
        };
        configure?.Invoke(settings);
        builder.Services.AddSingleton(Options.Create(settings));

        // Real (SQLite in-memory) DbContext — the reset path touches RefreshTokens.
        builder.Services.AddDbContext<DatabaseContext, TestDatabaseContext>(opt =>
            opt.UseSqlite(connection));

        builder.Services.AddSingleton<ILoggerFactory>(_ => NullLoggerFactory.Instance);

        var app = builder.Build();
        using (var scope = app.Services.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<DatabaseContext>().Database.EnsureCreated();
        }

        return (app, manager);
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
