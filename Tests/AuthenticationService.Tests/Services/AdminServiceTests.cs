using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Storage;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// Drives <see cref="AdminService"/> against SQLite-InMemory with stubbed UserManager / RoleManager /
/// IUserService / ITokenService / IEmailService. Focuses on the <c>CreateUserAsync</c> discriminated-union
/// outcomes, invitation-state guards, and cascade-on-state-change for the destructive endpoints.
/// </summary>
public class AdminServiceTests : IDisposable
{
    private const string AdminId = "admin-id";
    private const string TargetId = "target-id";

    [Fact]
    public async Task ListUsersAsync_AppliesSearchAndPagination_ReturnsExpectedSlice()
    {
        // arrange
        var (svc, db, _) = BuildService();
        await SeedUserAsync(db, "alice", "alice@example.com");
        await SeedUserAsync(db, "bob", "bob@example.com");
        await SeedUserAsync(db, "charlie", "charlie@example.com");

        // act
        var result = await svc.ListUsersAsync(new AdminListFilter { Search = "ali" }, CancellationToken.None);

        // assert
        result.TotalCount.Should().Be(1);
        result.Results.Should().ContainSingle(r => r.UserName == "alice");
    }

    [Fact]
    public async Task ListUsersAsync_LockedOnly_FiltersToLockedAccounts()
    {
        // arrange — three users: locked indefinitely (surface), locked-but-expired (skip), never locked (skip).
        // Identity uses far-future LockoutEnd sentinel for "permanently locked" rather than null-means-locked.
        var (svc, db, _) = BuildService();
        var locked = await SeedUserAsync(db, "locked", "locked@example.com");
        locked.LockoutEnd = DateTimeOffset.UtcNow.AddYears(10);
        var expired = await SeedUserAsync(db, "expired", "expired@example.com");
        expired.LockoutEnd = DateTimeOffset.UtcNow.AddDays(-1);
        await SeedUserAsync(db, "active", "active@example.com");
        await db.SaveChangesAsync();

        // act
        var result = await svc.ListUsersAsync(new AdminListFilter { LockedOnly = true }, CancellationToken.None);

        // assert
        result.TotalCount.Should().Be(1);
        result.Results.Should().ContainSingle();
        result.Results[0].UserName.Should().Be("locked");
        result.Results[0].IsLocked.Should().BeTrue(
            because: "the IsLocked projection mirrors the same LockoutEnd > now comparison used by the filter.");
    }

    [Fact]
    public async Task ListUsersAsync_PageSizeClampedToMax()
    {
        // arrange
        var (svc, db, _) = BuildService();
        for (var i = 0; i < 5; i++)
        {
            await SeedUserAsync(db, $"u{i}", $"u{i}@example.com");
        }

        // act
        var result = await svc.ListUsersAsync(
            new AdminListFilter { PageSize = AdminListFilter.MaxPageSize + 500 },
            CancellationToken.None);

        // assert
        result.PageSize.Should().Be(AdminListFilter.MaxPageSize,
            because: "PageSize must be clamped to the max so a client can't request unbounded pages");
    }

    [Fact]
    public async Task GetUserDetailAsync_UnknownUser_ReturnsNull()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        deps.UserManager.FindByIdAsync("ghost").Returns((User?)null);

        // act
        var result = await svc.GetUserDetailAsync("ghost", CancellationToken.None);

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetUserDetailAsync_KnownUser_PopulatesRolesAndActiveSessions()
    {
        // arrange
        var (svc, db, deps) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        deps.UserManager.FindByIdAsync(user.Id).Returns(user);
        deps.UserManager.GetRolesAsync(user).Returns(new List<string> { "DefaultUser" });

        // Two refresh-token families — one live, one consumed. Active count should be 1.
        db.RefreshTokens.AddRange(
            new RefreshToken { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = "h1", FamilyId = Guid.NewGuid(), CreatedAt = DateTime.UtcNow.AddMinutes(-1), ExpiresAt = DateTime.UtcNow.AddDays(1) },
            new RefreshToken { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = "h2", FamilyId = Guid.NewGuid(), CreatedAt = DateTime.UtcNow.AddMinutes(-5), ExpiresAt = DateTime.UtcNow.AddDays(1), ConsumedAt = DateTime.UtcNow.AddMinutes(-1) });
        await db.SaveChangesAsync();

        // act
        var result = await svc.GetUserDetailAsync(user.Id, CancellationToken.None);

        // assert
        result.Should().NotBeNull();
        result!.Roles.Should().Contain("DefaultUser");
        result.ActiveRefreshTokenFamilies.Should().Be(1,
            because: "only the unconsumed, not-yet-expired family should count toward active sessions");
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // CreateUserAsync — the discriminated-union outcomes
    // ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateUserAsync_AdminRoleRequested_ReturnsValidationFailed()
    {
        // arrange
        var (svc, _, _) = BuildService();

        // act
        var result = await svc.CreateUserAsync(
            new AdminCreateUserDto { Email = "x@example.com", UserName = "x", FirstName = "X", LastName = "Y", Roles = new List<string> { RolesConstants.Admin } },
            AdminId,
            DefaultCallerRoles,
            "10.0.0.1",
            CancellationToken.None);

        // assert
        result.Should().BeOfType<AdminCreateUserResult.ValidationFailed>(
            because: "the Admin role is seed-only and never assignable via API — not even by a PlatformAdmin");
    }

    [Fact]
    public async Task CreateUserAsync_PlatformAdminRoleRequested_ByAdmin_ReturnsValidationFailed()
    {
        // arrange — caller holds Admin but NOT PlatformAdmin. The endpoint is gated to
        // AdminOnly so the request lands; the service must still refuse the escalation.
        var (svc, _, _) = BuildService();

        // act
        var result = await svc.CreateUserAsync(
            new AdminCreateUserDto { Email = "x@example.com", UserName = "x", FirstName = "X", LastName = "Y", Roles = new List<string> { RolesConstants.PlatformAdmin } },
            AdminId,
            callerRoles: [RolesConstants.Admin],
            "10.0.0.1",
            CancellationToken.None);

        // assert
        var failure = result.Should().BeOfType<AdminCreateUserResult.ValidationFailed>(
            because: "an Admin caller without PlatformAdmin cannot create a user holding PlatformAdmin — that would be self-elevation by proxy")
            .Subject;
        failure.Errors.Should().ContainKey("roles");
        failure.Errors["roles"].Should().Contain(RolesConstants.PlatformAdmin);
    }

    [Fact]
    public async Task CreateUserAsync_PlatformAdminRoleRequested_ByPlatformAdmin_AllowsCreate()
    {
        // arrange — caller holds PlatformAdmin (and Admin too — that's how the seeded admin
        // is shaped). They should be able to mint a fellow PlatformAdmin.
        var (svc, _, deps) = BuildService();
        deps.RoleManager.RoleExistsAsync(RolesConstants.PlatformAdmin).Returns(true);
        deps.UserManager.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);
        deps.UserManager.FindByNameAsync(Arg.Any<string>()).Returns((User?)null);
        deps.UserService.CreateAsync(Arg.Any<User>()).Returns(ci =>
        {
            ci.Arg<User>().Id = "new-id";
            return IdentityResult.Success;
        });
        deps.UserManager.AddToRolesAsync(Arg.Any<User>(), Arg.Any<IEnumerable<string>>()).Returns(IdentityResult.Success);
        deps.UserManager.GeneratePasswordResetTokenAsync(Arg.Any<User>()).Returns("reset-token");

        // act
        var result = await svc.CreateUserAsync(
            new AdminCreateUserDto { Email = "x@example.com", UserName = "x", FirstName = "X", LastName = "Y", Roles = new List<string> { RolesConstants.PlatformAdmin } },
            AdminId,
            callerRoles: [RolesConstants.Admin, RolesConstants.PlatformAdmin],
            "10.0.0.1",
            CancellationToken.None);

        // assert
        result.Should().BeOfType<AdminCreateUserResult.Success>();
    }

    [Fact]
    public async Task CreateUserAsync_UnknownRoleRequested_ReturnsUnknownRole()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        deps.RoleManager.RoleExistsAsync("Wizard").Returns(false);

        // act
        var result = await svc.CreateUserAsync(
            new AdminCreateUserDto { Email = "x@example.com", UserName = "x", FirstName = "X", LastName = "Y", Roles = new List<string> { "Wizard" } },
            AdminId,
            DefaultCallerRoles,
            "10.0.0.1",
            CancellationToken.None);

        // assert
        result.Should().BeOfType<AdminCreateUserResult.UnknownRole>().Which.RoleName.Should().Be("Wizard");
    }

    [Fact]
    public async Task CreateUserAsync_DuplicateEmail_ReturnsConflict()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        deps.RoleManager.RoleExistsAsync(RolesConstants.DefaultUser).Returns(true);
        deps.UserManager.FindByEmailAsync("dup@example.com").Returns(new User());

        // act
        var result = await svc.CreateUserAsync(
            new AdminCreateUserDto { Email = "dup@example.com", UserName = "dup", FirstName = "X", LastName = "Y" },
            AdminId,
            DefaultCallerRoles,
            "10.0.0.1",
            CancellationToken.None);

        // assert
        result.Should().BeOfType<AdminCreateUserResult.Conflict>();
    }

    [Fact]
    public async Task CreateUserAsync_HappyPath_CreatesUserAddsRolesSendsEmail()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        deps.RoleManager.RoleExistsAsync(RolesConstants.DefaultUser).Returns(true);
        deps.UserManager.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);
        deps.UserManager.FindByNameAsync(Arg.Any<string>()).Returns((User?)null);
        deps.UserService.CreateAsync(Arg.Any<User>()).Returns(ci =>
        {
            // Mimic Identity stamping an Id on the entity.
            ci.Arg<User>().Id = "new-id";
            return IdentityResult.Success;
        });
        deps.UserManager.AddToRolesAsync(Arg.Any<User>(), Arg.Any<IEnumerable<string>>()).Returns(IdentityResult.Success);
        deps.UserManager.GeneratePasswordResetTokenAsync(Arg.Any<User>()).Returns("reset-token");

        // act
        var result = await svc.CreateUserAsync(
            new AdminCreateUserDto { Email = "alice@example.com", UserName = "alice", FirstName = "A", LastName = "B" },
            AdminId,
            DefaultCallerRoles,
            "10.0.0.1",
            CancellationToken.None);

        // assert
        result.Should().BeOfType<AdminCreateUserResult.Success>().Which.UserId.Should().Be("new-id");
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com",
            EmailSubjects.AccountInvitation,
            Arg.Is<string>(body => body.Contains("activate your account")));
    }

    [Fact]
    public async Task CreateUserAsync_AddToRolesFails_DeletesUserToRollBack()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        deps.RoleManager.RoleExistsAsync(RolesConstants.DefaultUser).Returns(true);
        deps.UserManager.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);
        deps.UserManager.FindByNameAsync(Arg.Any<string>()).Returns((User?)null);
        deps.UserService.CreateAsync(Arg.Any<User>()).Returns(IdentityResult.Success);
        deps.UserManager.AddToRolesAsync(Arg.Any<User>(), Arg.Any<IEnumerable<string>>())
            .Returns(IdentityResult.Failed(new IdentityError { Code = "boom", Description = "no" }));

        // act
        var result = await svc.CreateUserAsync(
            new AdminCreateUserDto { Email = "x@example.com", UserName = "x", FirstName = "X", LastName = "Y" },
            AdminId,
            DefaultCallerRoles,
            "10.0.0.1",
            CancellationToken.None);

        // assert
        result.Should().BeOfType<AdminCreateUserResult.IdentityFailed>();
        await deps.UserManager.Received(1).DeleteAsync(Arg.Any<User>());
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // ResendInvitationAsync
    // ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ResendInvitationAsync_UserNotFound_ReturnsNotFound()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        deps.UserManager.FindByIdAsync(TargetId).Returns((User?)null);

        // act
        var result = await svc.ResendInvitationAsync(TargetId, AdminId, "10.0.0.1", CancellationToken.None);

        // assert
        result.Should().Be(AdminInvitationResendResult.UserNotFound);
    }

    [Fact]
    public async Task ResendInvitationAsync_UserAlreadyConfirmed_ReturnsAlreadyActive()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        deps.UserManager.FindByIdAsync(TargetId).Returns(new User { Id = TargetId, EmailConfirmed = true, PasswordHash = null });

        // act
        var result = await svc.ResendInvitationAsync(TargetId, AdminId, "10.0.0.1", CancellationToken.None);

        // assert
        result.Should().Be(AdminInvitationResendResult.UserAlreadyActive);
    }

    [Fact]
    public async Task ResendInvitationAsync_UserHasPasswordHash_ReturnsAlreadyActive()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        deps.UserManager.FindByIdAsync(TargetId).Returns(new User { Id = TargetId, EmailConfirmed = false, PasswordHash = "hash" });

        // act
        var result = await svc.ResendInvitationAsync(TargetId, AdminId, "10.0.0.1", CancellationToken.None);

        // assert
        result.Should().Be(AdminInvitationResendResult.UserAlreadyActive);
    }

    [Fact]
    public async Task ResendInvitationAsync_PendingInvitation_ResendsEmail()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        var user = new User { Id = TargetId, Email = "alice@example.com", EmailConfirmed = false, PasswordHash = null };
        deps.UserManager.FindByIdAsync(TargetId).Returns(user);
        deps.UserManager.GeneratePasswordResetTokenAsync(user).Returns("token");

        // act
        var result = await svc.ResendInvitationAsync(TargetId, AdminId, "10.0.0.1", CancellationToken.None);

        // assert
        result.Should().Be(AdminInvitationResendResult.Resent);
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com",
            EmailSubjects.AccountInvitation,
            Arg.Any<string>());
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // State-changing endpoints
    // ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LockUserAsync_NotFound_ReturnsNull()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        deps.UserManager.FindByIdAsync(TargetId).Returns((User?)null);

        // act
        var result = await svc.LockUserAsync(TargetId, AdminId, "10.0.0.1", CancellationToken.None);

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task LockUserAsync_HappyPath_SetsIndefiniteLockoutAndReturnsInfo()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        var user = new User { Id = TargetId };
        deps.UserManager.FindByIdAsync(TargetId).Returns(user);

        // act
        var result = await svc.LockUserAsync(TargetId, AdminId, "10.0.0.1", CancellationToken.None);

        // assert
        result.Should().NotBeNull();
        await deps.UserManager.Received(1).SetLockoutEnabledAsync(user, true);
        await deps.UserManager.Received(1).SetLockoutEndDateAsync(user, LockoutDurations.Indefinite);
    }

    [Fact]
    public async Task UnlockUserAsync_HappyPath_ClearsLockoutAndCounter()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        var user = new User { Id = TargetId, LockoutEnd = DateTimeOffset.UtcNow.AddDays(1), AccessFailedCount = 3 };
        deps.UserManager.FindByIdAsync(TargetId).Returns(user);

        // act
        var result = await svc.UnlockUserAsync(TargetId, AdminId, "10.0.0.1", CancellationToken.None);

        // assert
        result.Should().NotBeNull();
        user.LockoutEnd.Should().BeNull();
        user.AccessFailedCount.Should().Be(0);
        await deps.UserManager.Received(1).UpdateAsync(user);
    }

    [Fact]
    public async Task RevokeSessionsAsync_HappyPath_DelegatesToInvalidateUserTokens()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        var user = new User { Id = TargetId };
        deps.UserManager.FindByIdAsync(TargetId).Returns(user);

        // act
        var result = await svc.RevokeSessionsAsync(TargetId, AdminId, "10.0.0.1", CancellationToken.None);

        // assert
        result.Should().BeTrue();
        await deps.UserService.Received(1).InvalidateUserTokensAsync(user, "10.0.0.1", RevocationReasons.AdminRevokedSessions);
    }

    [Fact]
    public async Task ResetMfaAsync_HappyPath_DisablesMfaResetsKeyAndRevokesSessions()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        var user = new User { Id = TargetId };
        deps.UserManager.FindByIdAsync(TargetId).Returns(user);

        // act
        var result = await svc.ResetMfaAsync(TargetId, AdminId, "10.0.0.1", CancellationToken.None);

        // assert
        result.Should().BeTrue();
        await deps.UserManager.Received(1).SetTwoFactorEnabledAsync(user, false);
        await deps.UserManager.Received(1).ResetAuthenticatorKeyAsync(user);
        await deps.UserService.Received(1).InvalidateUserTokensAsync(user, "10.0.0.1", RevocationReasons.AdminResetMfa);
    }

    [Fact]
    public async Task ForcePasswordResetAsync_HappyPath_SendsResetEmailAndRevokesRefreshTokens()
    {
        // arrange
        var (svc, _, deps) = BuildService();
        var user = new User { Id = TargetId, Email = "alice@example.com" };
        deps.UserManager.FindByIdAsync(TargetId).Returns(user);
        deps.UserManager.GeneratePasswordResetTokenAsync(user).Returns("token");

        // act
        var result = await svc.ForcePasswordResetAsync(TargetId, AdminId, "10.0.0.1", callbackUri: null, CancellationToken.None);

        // assert
        result.Should().BeTrue();
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com",
            EmailSubjects.PasswordReset,
            Arg.Is<string>(body => body.Contains("administrator has initiated")));
        // Refresh-token revocation only — security-stamp rotation is deferred to the user's reset-password completion
        // so the just-generated reset token stays valid through the round trip.
        await deps.TokenService.Received(1).RevokeAllRefreshTokenFamiliesAsync(
            TargetId, RevocationReasons.AdminForcedPasswordReset);
        await deps.UserService.DidNotReceiveWithAnyArgs().InvalidateUserTokensAsync(
            default!, default!, default!, default);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // Audit
    // ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetAuditAsync_UnknownUser_ReturnsNull()
    {
        // arrange
        var (svc, _, _) = BuildService();

        // act
        var result = await svc.GetAuditAsync(new AdminAuditFilter { UserId = "ghost" }, CancellationToken.None);

        // assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetAuditAsync_FiltersByUserAndOrdersDescending()
    {
        // arrange
        var (svc, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        db.SecurityEvents.AddRange(
            new SecurityEvent { UserId = user.Id, EventId = 1001, EventName = "LoginSucceeded", Level = "Information", Timestamp = DateTime.UtcNow.AddMinutes(-30) },
            new SecurityEvent { UserId = user.Id, EventId = 1002, EventName = "LoginFailed", Level = "Warning", Timestamp = DateTime.UtcNow.AddMinutes(-10) },
            new SecurityEvent { UserId = "other", EventId = 1001, EventName = "LoginSucceeded", Level = "Information", Timestamp = DateTime.UtcNow });
        await db.SaveChangesAsync();

        // act
        var result = await svc.GetAuditAsync(new AdminAuditFilter { UserId = user.Id }, CancellationToken.None);

        // assert
        result.Should().NotBeNull();
        result!.TotalCount.Should().Be(2);
        result.Results.Select(r => r.EventId).Should().Equal(new[] { 1002, 1001 },
            because: "rows must be ordered by Timestamp DESC and filtered to the target user");
    }

    [Fact]
    public async Task GetAuditAsync_PropertiesJsonExpandedIntoFields()
    {
        // arrange
        var (svc, db, _) = BuildService();
        var user = await SeedUserAsync(db, "alice", "alice@example.com");
        db.SecurityEvents.Add(new SecurityEvent
        {
            UserId = user.Id,
            EventId = 1008,
            EventName = "RefreshTokenReuseDetected",
            Level = "Critical",
            Timestamp = DateTime.UtcNow,
            PropertiesJson = "{\"FamilyId\":\"abc-123\",\"Reason\":\"reuse\"}",
        });
        await db.SaveChangesAsync();

        // act
        var result = await svc.GetAuditAsync(new AdminAuditFilter { UserId = user.Id }, CancellationToken.None);

        // assert
        result!.Results.Should().ContainSingle();
        result.Results[0].Fields.Should().Contain(new KeyValuePair<string, string?>("FamilyId", "abc-123"));
        result.Results[0].Fields.Should().Contain(new KeyValuePair<string, string?>("Reason", "reuse"));
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────────

    private (AdminService service, DatabaseContext db, ServiceDeps deps) BuildService()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        // TestDatabaseContext applies the LockoutEnd → UtcTicks converter so the LockedOnly filter's DateTimeOffset
        // binary comparison is translatable by the SQLite EF provider.
        var options = new DbContextOptionsBuilder<TestDatabaseContext>().UseSqlite(connection).Options;
        var db = new TestDatabaseContext(options);
        db.Database.EnsureCreated();
        _contexts.Add(db);

        var deps = new ServiceDeps
        {
            UserManager = StubUserManager(),
            RoleManager = StubRoleManager(),
            UserService = Substitute.For<IUserService>(),
            TokenService = Substitute.For<ITokenService>(),
            EmailService = Substitute.For<IEmailService>(),
        };

        // Default role check is "yes, this exists" so happy-path tests don't have to opt in for every role.
        deps.RoleManager.RoleExistsAsync(Arg.Any<string>()).Returns(true);

        var publicUrl = Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" });
        var service = new AdminService(
            db,
            deps.UserManager,
            deps.RoleManager,
            deps.UserService,
            deps.TokenService,
            deps.EmailService,
            new RoleAssignmentPolicy(),
            publicUrl,
            TestMetricsFactory.Create(),
            NullLogger<AdminService>.Instance);

        return (service, db, deps);
    }

    // Default caller-roles for invitation-flow tests — Admin holder. Mirrors the seeded
    // admin's role set (Admin + DefaultUser + PlatformAdmin); individual tests override
    // when they want to assert escalation behaviour.
    private static readonly string[] DefaultCallerRoles = [RolesConstants.Admin];

    private static UserManager<User> StubUserManager()
    {
        var store = Substitute.For<IUserStore<User>>();
        var manager = Substitute.For<UserManager<User>>(store, null!, null!, null!, null!, null!, null!, null!, null!);
        return manager;
    }

    private static RoleManager<Role> StubRoleManager()
    {
        var store = Substitute.For<IRoleStore<Role>>();
        var manager = Substitute.For<RoleManager<Role>>(store, null!, null!, null!, null!);
        return manager;
    }

    private static async Task<User> SeedUserAsync(DatabaseContext db, string userName, string email)
    {
        var user = new User
        {
            Id = Guid.NewGuid().ToString(),
            UserName = userName,
            Email = email,
            NormalizedUserName = userName.ToUpperInvariant(),
            NormalizedEmail = email.ToUpperInvariant(),
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }

    private sealed class ServiceDeps
    {
        public UserManager<User> UserManager { get; set; } = default!;
        public RoleManager<Role> RoleManager { get; set; } = default!;
        public IUserService UserService { get; set; } = default!;
        public ITokenService TokenService { get; set; } = default!;
        public IEmailService EmailService { get; set; } = default!;
    }

    private readonly List<SqliteConnection> _connections = new();
    private readonly List<DatabaseContext> _contexts = new();

    public void Dispose()
    {
        foreach (var ctx in _contexts) { try { ctx.Dispose(); } catch { } }
        foreach (var conn in _connections) { try { conn.Dispose(); } catch { } }
        GC.SuppressFinalize(this);
    }
}
