using System.Security.Claims;
using AuthenticationService.Constants;
using AuthenticationService.Controllers;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using Microsoft.EntityFrameworkCore;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// Controller-layer tests for <see cref="AdminController"/>: self-protection guards on destructive
/// endpoints, service-result → HTTP status mapping, parameter pass-through. The auth gate itself
/// is integration-tested, not here.
/// </summary>
public class AdminControllerTests
{
    private const string AdminId = "admin-1";
    private const string OtherUserId = "user-2";

    // ──────────────────────────────────────────────────────────────────────────────
    // List + Detail
    // ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ListUsersAsync_PassesQueryParamsThroughToFilter()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.ListUsersAsync(Arg.Any<AdminListFilter>(), Arg.Any<CancellationToken>())
            .Returns(new PagedResponse<UserSummaryDto>());

        var result = await controller.ListUsersAsync(
            page: 3,
            pageSize: 50,
            search: "alice",
            lockedOnly: true,
            unconfirmedOnly: false);

        result.Should().BeOfType<OkObjectResult>();
        await deps.AdminService.Received(1).ListUsersAsync(
            Arg.Is<AdminListFilter>(f =>
                f.Page == 3 &&
                f.PageSize == 50 &&
                f.Search == "alice" &&
                f.LockedOnly &&
                !f.UnconfirmedOnly),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetUserAsync_ServiceReturnsDetail_ReturnsOkWithBody()
    {
        var (controller, deps) = BuildController();
        var detail = new UserDetailDto { Id = OtherUserId };
        deps.AdminService.GetUserDetailAsync(OtherUserId, Arg.Any<CancellationToken>()).Returns(detail);

        var result = await controller.GetUserAsync(OtherUserId, CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>().Which.Value.Should().BeSameAs(detail);
    }

    [Fact]
    public async Task GetUserAsync_ServiceReturnsNull_Returns404()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.GetUserDetailAsync(OtherUserId, Arg.Any<CancellationToken>()).Returns((UserDetailDto?)null);

        var result = await controller.GetUserAsync(OtherUserId, CancellationToken.None);

        result.Should().BeOfType<NotFoundResult>();
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // Self-protection
    // ──────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("lock")]
    [InlineData("unlock")]
    [InlineData("revoke-sessions")]
    [InlineData("reset-mfa")]
    [InlineData("force-password-reset")]
    [InlineData("resend-invitation")]
    public async Task DestructiveEndpoints_RejectSelfTarget(string action)
    {
        var (controller, deps) = BuildController();

        IActionResult result = action switch
        {
            "lock" => await controller.LockUserAsync(AdminId, CancellationToken.None),
            "unlock" => await controller.UnlockUserAsync(AdminId, CancellationToken.None),
            "revoke-sessions" => await controller.RevokeSessionsAsync(AdminId, CancellationToken.None),
            "reset-mfa" => await controller.ResetMfaAsync(AdminId, CancellationToken.None),
            "force-password-reset" => await controller.ForcePasswordResetAsync(AdminId, request: null, CancellationToken.None),
            "resend-invitation" => await controller.ResendInvitationAsync(AdminId, CancellationToken.None),
            _ => throw new InvalidOperationException(action)
        };

        result.Should().BeOfType<BadRequestObjectResult>(
            because: "destructive operations on the current admin must be blocked before reaching the service");
        await deps.AdminService.DidNotReceiveWithAnyArgs().LockUserAsync(default!, default!, default!, default);
        await deps.AdminService.DidNotReceiveWithAnyArgs().UnlockUserAsync(default!, default!, default!, default);
        await deps.AdminService.DidNotReceiveWithAnyArgs().RevokeSessionsAsync(default!, default!, default!, default);
        await deps.AdminService.DidNotReceiveWithAnyArgs().ResetMfaAsync(default!, default!, default!, default);
        await deps.AdminService.DidNotReceiveWithAnyArgs().ForcePasswordResetAsync(default!, default!, default!, default, default);
        await deps.AdminService.DidNotReceiveWithAnyArgs().ResendInvitationAsync(default!, default!, default!, default);
    }

    [Fact]
    public async Task GetUserAsync_AllowsSelfTarget()
    {
        // List / detail / audit are non-destructive — admins can audit their own activity.
        var (controller, deps) = BuildController();
        deps.AdminService.GetUserDetailAsync(AdminId, Arg.Any<CancellationToken>())
            .Returns(new UserDetailDto { Id = AdminId });

        var result = await controller.GetUserAsync(AdminId, CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>();
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // Lock / Unlock
    // ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LockUserAsync_NotFound_Returns404()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.LockUserAsync(OtherUserId, AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((LockoutInfoDto?)null);

        var result = await controller.LockUserAsync(OtherUserId, CancellationToken.None);

        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task LockUserAsync_HappyPath_ReturnsOkWithLockoutInfo()
    {
        var (controller, deps) = BuildController();
        var info = new LockoutInfoDto { IsLocked = true };
        deps.AdminService.LockUserAsync(OtherUserId, AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(info);

        var result = await controller.LockUserAsync(OtherUserId, CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>().Which.Value.Should().BeSameAs(info);
    }

    [Fact]
    public async Task UnlockUserAsync_HappyPath_ReturnsOkWithLockoutInfo()
    {
        var (controller, deps) = BuildController();
        var info = new LockoutInfoDto { IsLocked = false };
        deps.AdminService.UnlockUserAsync(OtherUserId, AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(info);

        var result = await controller.UnlockUserAsync(OtherUserId, CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>();
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // CreateUser — discriminated-union mapping
    // ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateUserAsync_Success_Returns201WithLocation()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.CreateUserAsync(Arg.Any<AdminCreateUserDto>(), AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new AdminCreateUserResult.Success("new-user-id"));

        var result = await controller.CreateUserAsync(new AdminCreateUserDto(), CancellationToken.None);

        var created = result.Should().BeOfType<CreatedResult>().Subject;
        created.Location.Should().Be("/api/Admin/users/new-user-id");
    }

    [Fact]
    public async Task CreateUserAsync_ValidationFailed_Returns400WithErrors()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.CreateUserAsync(Arg.Any<AdminCreateUserDto>(), AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new AdminCreateUserResult.ValidationFailed(new Dictionary<string, string> { ["roles"] = "bad" }));

        var result = await controller.CreateUserAsync(new AdminCreateUserDto(), CancellationToken.None);

        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<ApiResponse>().Which.Errors.Should().ContainKey("roles");
    }

    [Fact]
    public async Task CreateUserAsync_UnknownRole_Returns400WithRoleError()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.CreateUserAsync(Arg.Any<AdminCreateUserDto>(), AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new AdminCreateUserResult.UnknownRole("Wizard"));

        var result = await controller.CreateUserAsync(new AdminCreateUserDto(), CancellationToken.None);

        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<ApiResponse>().Which.Errors.Should().ContainKey("roles");
    }

    [Fact]
    public async Task CreateUserAsync_Conflict_Returns409()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.CreateUserAsync(Arg.Any<AdminCreateUserDto>(), AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new AdminCreateUserResult.Conflict("email taken"));

        var result = await controller.CreateUserAsync(new AdminCreateUserDto(), CancellationToken.None);

        result.Should().BeOfType<ConflictObjectResult>();
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // Resend / Revoke / Reset / ForcePasswordReset / Audit — mapping spot-checks
    // ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ResendInvitationAsync_UserAlreadyActive_Returns409()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.ResendInvitationAsync(OtherUserId, AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(AdminInvitationResendResult.UserAlreadyActive);

        var result = await controller.ResendInvitationAsync(OtherUserId, CancellationToken.None);

        result.Should().BeOfType<ConflictObjectResult>();
    }

    [Fact]
    public async Task ResendInvitationAsync_UserNotFound_Returns404()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.ResendInvitationAsync(OtherUserId, AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(AdminInvitationResendResult.UserNotFound);

        var result = await controller.ResendInvitationAsync(OtherUserId, CancellationToken.None);

        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task RevokeSessionsAsync_HappyPath_ReturnsOk()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.RevokeSessionsAsync(OtherUserId, AdminId, Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(true);

        var result = await controller.RevokeSessionsAsync(OtherUserId, CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>();
    }

    [Fact]
    public async Task ForcePasswordResetAsync_CallbackUriPassesThrough()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.ForcePasswordResetAsync(OtherUserId, AdminId, Arg.Any<string>(), "https://override.test", Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await controller.ForcePasswordResetAsync(
            OtherUserId,
            new AdminController.ForcePasswordResetRequest { CallbackUri = "https://override.test" },
            CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>();
        await deps.AdminService.Received(1).ForcePasswordResetAsync(
            OtherUserId, AdminId, Arg.Any<string>(), "https://override.test", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetAuditAsync_PassesFilterThroughAndReturnsResult()
    {
        var (controller, deps) = BuildController();
        var paged = new PagedResponse<AuditEntryDto>();
        deps.AdminService.GetAuditAsync(Arg.Any<AdminAuditFilter>(), Arg.Any<CancellationToken>()).Returns(paged);

        var result = await controller.GetAuditAsync(OtherUserId, page: 2, pageSize: 25, since: null, eventId: 1001);

        result.Should().BeOfType<OkObjectResult>().Which.Value.Should().BeSameAs(paged);
        await deps.AdminService.Received(1).GetAuditAsync(
            Arg.Is<AdminAuditFilter>(f =>
                f.UserId == OtherUserId &&
                f.Page == 2 &&
                f.PageSize == 25 &&
                f.EventId == 1001),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetAuditAsync_NotFound_Returns404()
    {
        var (controller, deps) = BuildController();
        deps.AdminService.GetAuditAsync(Arg.Any<AdminAuditFilter>(), Arg.Any<CancellationToken>())
            .Returns((PagedResponse<AuditEntryDto>?)null);

        var result = await controller.GetAuditAsync(OtherUserId);

        result.Should().BeOfType<NotFoundResult>();
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // OAuth client management (Phase 1)
    // ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateClientAsync_HappyPath_Returns201WithPlaintextSecret()
    {
        var (controller, deps) = BuildController();
        // NSubstitute requires uniform specifiers when any argument of a given type uses Arg.Any.
        deps.ClientService.CreateAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string?>(),
                Arg.Any<IEnumerable<(string, string)>>(), Arg.Any<CancellationToken>())
            .Returns(new AuthenticationService.Entities.Client
            {
                Id = "c",
                Name = "Test",
                ClientSecretHash = "hash",
            });

        var result = await controller.CreateClientAsync(
            new AdminCreateClientDto { Id = "c", Name = "Test" }, CancellationToken.None);

        var created = result.Should().BeOfType<CreatedResult>().Subject;
        var body = created.Value.Should().BeOfType<ClientCreatedResponse>().Subject;
        body.Id.Should().Be("c");
        body.ClientSecret.Should().NotBeNullOrEmpty(
            because: "create-client must return the plaintext secret in the response (one-time display).");
    }

    [Fact]
    public async Task CreateClientAsync_MissingId_Returns400()
    {
        var (controller, _) = BuildController();

        var result = await controller.CreateClientAsync(
            new AdminCreateClientDto { Id = null, Name = "Test" }, CancellationToken.None);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task RotateClientSecretAsync_UnknownClient_Returns404()
    {
        var (controller, deps) = BuildController();
        deps.ClientService.RotateSecretAsync("ghost", Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((AuthenticationService.Entities.Client?)null);

        var result = await controller.RotateClientSecretAsync("ghost", CancellationToken.None);

        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task RotateClientSecretAsync_HappyPath_ReturnsNewSecret()
    {
        var (controller, deps) = BuildController();
        deps.ClientService.RotateSecretAsync("c", Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new AuthenticationService.Entities.Client { Id = "c", Name = "T", ClientSecretHash = "h" });

        var result = await controller.RotateClientSecretAsync("c", CancellationToken.None);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var body = ok.Value.Should().BeOfType<ClientCreatedResponse>().Subject;
        body.ClientSecret.Should().NotBeNullOrEmpty(
            because: "rotate-secret returns the new plaintext (same one-time-display contract as create).");
    }

    [Fact]
    public async Task DisableClientAsync_ChangedFlag_ReturnsOk()
    {
        var (controller, deps) = BuildController();
        deps.ClientService.DisableAsync("c", Arg.Any<CancellationToken>()).Returns(true);

        var result = await controller.DisableClientAsync("c", CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>();
    }

    [Fact]
    public async Task AddClientScopeAsync_ValidationFailure_Returns400()
    {
        var (controller, _) = BuildController();

        var result = await controller.AddClientScopeAsync(
            "c", new AdminClientScopeDto { Audience = null, Scope = null }, CancellationToken.None);

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task AddClientScopeAsync_HappyPath_DelegatesAndReturnsOk()
    {
        var (controller, deps) = BuildController();
        deps.ClientService.AddScopeAsync("c", "aud", "scope", Arg.Any<CancellationToken>()).Returns(true);

        var result = await controller.AddClientScopeAsync(
            "c", new AdminClientScopeDto { Audience = "aud", Scope = "scope" }, CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>();
        await deps.ClientService.Received(1).AddScopeAsync("c", "aud", "scope", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RemoveClientScopeAsync_NotPresent_Returns404()
    {
        var (controller, deps) = BuildController();
        deps.ClientService.RemoveScopeAsync(
                "c", "aud", "scope", Arg.Any<CancellationToken>())
            .Returns(false);

        var result = await controller.RemoveClientScopeAsync("c", "aud", "scope", CancellationToken.None);

        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task RemoveClientScopeAsync_HappyPath_ReturnsOk()
    {
        var (controller, deps) = BuildController();
        deps.ClientService.RemoveScopeAsync(
                "c", "aud", "scope", Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await controller.RemoveClientScopeAsync("c", "aud", "scope", CancellationToken.None);

        result.Should().BeOfType<OkObjectResult>();
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────────

    private static (AdminController controller, Deps deps) BuildController()
    {
        var deps = new Deps
        {
            AdminService = Substitute.For<IAdminService>(),
            ClientService = Substitute.For<IClientService>(),
        };

        // Empty SQLite DB for the (rare) tests that query DatabaseContext directly via client-list endpoints.
        var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
        connection.Open();
        var dbOpt = new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<AuthenticationService.Storage.DatabaseContext>()
            .UseSqlite(connection)
            .Options;
        var db = new AuthenticationService.Storage.DatabaseContext(dbOpt);
        db.Database.EnsureCreated();

        var controller = new AdminController(
            deps.AdminService,
            deps.ClientService,
            db,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<AdminController>.Instance);

        var claims = new[] { new Claim(ClaimConstants.Sub, AdminId) };
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "test")),
                Connection = { RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.5") }
            }
        };
        return (controller, deps);
    }

    private sealed class Deps
    {
        public IAdminService AdminService { get; set; } = default!;
        public IClientService ClientService { get; set; } = default!;
    }
}
