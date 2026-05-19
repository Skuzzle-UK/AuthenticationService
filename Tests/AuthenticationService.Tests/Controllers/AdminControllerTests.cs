using System.Security.Claims;
using AuthenticationService.Constants;
using AuthenticationService.Controllers;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// <para>Controller-layer tests for <see cref="AdminController"/>. Focused on three things:</para>
/// <list type="bullet">
///   <item><description>Self-protection — destructive endpoints reject when target == current admin.</description></item>
///   <item><description>Status mapping — each service result variant maps to the right HTTP status.</description></item>
///   <item><description>Parameter pass-through — query params land in the right service filter, body fields flow through.</description></item>
/// </list>
/// <para>The auth gate (<c>[Authorize(Policy = AdminOnly)]</c>) is wired by ASP.NET Core's
/// authorisation middleware, not by code we own — covered by the integration scenarios, not
/// here.</para>
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
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────────

    private static (AdminController controller, Deps deps) BuildController()
    {
        var deps = new Deps
        {
            AdminService = Substitute.For<IAdminService>(),
        };

        var controller = new AdminController(deps.AdminService);

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
    }
}
