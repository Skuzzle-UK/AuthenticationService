using AuthenticationService.Constants;
using AuthenticationService.Extensions;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace AuthenticationService.Controllers;

/// <summary>
/// Admin user-management endpoints. All actions require the <see cref="PolicyConstants.AdminOnly"/>
/// policy (which ties to the <c>Admin</c> role on the calling principal). Destructive
/// actions refuse self-target so an admin can't fat-finger themselves out of the system.
[Route("api/[controller]")]
[ApiController]
[Authorize(Policy = PolicyConstants.AdminOnly)]
[EnableRateLimiting(RateLimitPolicies.AuthSensitive)]
public class AdminController : ControllerBase
{
    private readonly IAdminService _adminService;

    public AdminController(IAdminService adminService)
    {
        _adminService = adminService;
    }

    /// <summary>
    /// Paginated list of users with optional filters (search, locked-only, unconfirmed-only).
    /// </summary>
    [HttpGet("users")]
    public async Task<IActionResult> ListUsersAsync(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = AdminListFilter.DefaultPageSize,
        [FromQuery] string? search = null,
        [FromQuery] bool lockedOnly = false,
        [FromQuery] bool unconfirmedOnly = false,
        CancellationToken ct = default)
    {
        var result = await _adminService.ListUsersAsync(new AdminListFilter
        {
            Page = page,
            PageSize = pageSize,
            Search = search,
            LockedOnly = lockedOnly,
            UnconfirmedOnly = unconfirmedOnly,
        }, ct);

        return Ok(result);
    }

    /// <summary>
    /// Full detail for a single user — profile, lockout state, MFA, roles, active session count.
    /// </summary>
    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUserAsync(string id, CancellationToken ct)
    {
        var detail = await _adminService.GetUserDetailAsync(id, ct);
        return detail is null ? NotFound() : Ok(detail);
    }

    /// <summary>
    /// Creates a new user via the invitation flow. The user gets an email with a link to
    /// set their initial password; the account is unusable until they do.
    /// </summary>
    [HttpPost("users")]
    public async Task<IActionResult> CreateUserAsync(
        [FromBody] AdminCreateUserDto request,
        CancellationToken ct)
    {
        var result = await _adminService.CreateUserAsync(
            request,
            adminUserId: GetCurrentAdminId(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return result switch
        {
            AdminCreateUserResult.Success s => Created($"/api/Admin/users/{s.UserId}",
                new ApiResponse().Successful()),
            AdminCreateUserResult.ValidationFailed v => BadRequest(new ApiResponse().AddErrors(v.Errors.ToDictionary(kv => kv.Key, kv => kv.Value))),
            AdminCreateUserResult.UnknownRole u => BadRequest(new ApiResponse().AddError("roles", $"Unknown role '{u.RoleName}'.")),
            AdminCreateUserResult.Conflict c => Conflict(new ApiResponse().AddError("conflict", c.Reason)),
            AdminCreateUserResult.IdentityFailed f => BadRequest(new ApiResponse().AddErrors(f.IdentityErrors.ToDictionary(e => e.Code, e => e.Description))),
            _ => StatusCode(500),
        };
    }

    /// <summary>
    /// Re-sends the invitation email for a user still in the pending-invitation state.
    /// Returns 409 if the user has already accepted (or otherwise activated their account).
    /// </summary>
    [HttpPost("users/{id}/resend-invitation")]
    public async Task<IActionResult> ResendInvitationAsync(string id, CancellationToken ct)
    {
        if (RejectIfSelf(id, out var selfResponse))
        {
            return selfResponse;
        }

        var result = await _adminService.ResendInvitationAsync(
            targetUserId: id,
            adminUserId: GetCurrentAdminId(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return result switch
        {
            AdminInvitationResendResult.Resent => Ok(new ApiResponse()),
            AdminInvitationResendResult.UserNotFound => NotFound(),
            AdminInvitationResendResult.UserAlreadyActive => Conflict(new ApiResponse()
                .AddError("user_already_active", "User has already activated their account; invitation no longer applies.")),
            _ => StatusCode(500),
        };
    }

    /// <summary>
    /// Locks a user account indefinitely. Refuses self-target.
    /// </summary>
    [HttpPost("users/{id}/lock")]
    public async Task<IActionResult> LockUserAsync(string id, CancellationToken ct)
    {
        if (RejectIfSelf(id, out var selfResponse))
        {
            return selfResponse;
        }

        var info = await _adminService.LockUserAsync(
            targetUserId: id,
            adminUserId: GetCurrentAdminId(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return info is null ? NotFound() : Ok(info);
    }

    /// <summary>
    /// Lifts an active lockout and resets the failed-attempt counter.
    /// Refuses self-target (admins use the seed-account recovery path, not this endpoint).
    /// </summary>
    [HttpPost("users/{id}/unlock")]
    public async Task<IActionResult> UnlockUserAsync(string id, CancellationToken ct)
    {
        if (RejectIfSelf(id, out var selfResponse))
        {
            return selfResponse;
        }

        var info = await _adminService.UnlockUserAsync(
            targetUserId: id,
            adminUserId: GetCurrentAdminId(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return info is null ? NotFound() : Ok(info);
    }

    /// <summary>
    /// Revokes every active session the user has — refresh-token families + rotates the security
    /// stamp. The "log them out everywhere" hammer. Doesn't lock the account; user can sign back in.
    /// </summary>
    [HttpPost("users/{id}/revoke-sessions")]
    public async Task<IActionResult> RevokeSessionsAsync(string id, CancellationToken ct)
    {
        if (RejectIfSelf(id, out var selfResponse))
        {
            return selfResponse;
        }

        var ok = await _adminService.RevokeSessionsAsync(
            targetUserId: id,
            adminUserId: GetCurrentAdminId(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return ok ? Ok(new ApiResponse()) : NotFound();
    }

    /// <summary>
    /// Disables the user's MFA and clears their authenticator key. Used by helpdesk for lost-phone
    /// recovery. Revokes all sessions implicitly.
    /// </summary>
    [HttpPost("users/{id}/reset-mfa")]
    public async Task<IActionResult> ResetMfaAsync(string id, CancellationToken ct)
    {
        if (RejectIfSelf(id, out var selfResponse))
        {
            return selfResponse;
        }

        var ok = await _adminService.ResetMfaAsync(
            targetUserId: id,
            adminUserId: GetCurrentAdminId(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return ok ? Ok(new ApiResponse()) : NotFound();
    }

    /// <summary>
    /// Force-password-reset — generates an Identity reset token, emails it to the user, and
    /// revokes the user's existing sessions. Admin never sees the new password (user picks it
    /// themselves via the reset-password page).
    /// </summary>
    [HttpPost("users/{id}/force-password-reset")]
    public async Task<IActionResult> ForcePasswordResetAsync(
        string id,
        [FromBody] ForcePasswordResetRequest? request,
        CancellationToken ct)
    {
        if (RejectIfSelf(id, out var selfResponse))
        {
            return selfResponse;
        }

        var ok = await _adminService.ForcePasswordResetAsync(
            targetUserId: id,
            adminUserId: GetCurrentAdminId(),
            ipAddress: Request.GetRemoteIpAddress(),
            callbackUri: request?.CallbackUri,
            ct);

        return ok ? Ok(new ApiResponse()) : NotFound();
    }

    /// <summary>
    /// Body shape for the optional callback override on force-password-reset. Sits in the
    /// controller because it's only used here; a top-level DTO felt like overkill.
    /// </summary>
    public sealed class ForcePasswordResetRequest
    {
        public string? CallbackUri { get; set; }
    }

    /// <summary>
    /// Paginated audit log for the user — reads from the <c>SecurityEvents</c> table
    /// populated by the custom Serilog sink. Defaults to the last 30 days of events;
    /// passes <see cref="AdminAuditFilter"/> through to the service.
    /// </summary>
    [HttpGet("users/{id}/audit")]
    public async Task<IActionResult> GetAuditAsync(
        string id,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = AdminAuditFilter.DefaultPageSize,
        [FromQuery] DateTime? since = null,
        [FromQuery] int? eventId = null,
        CancellationToken ct = default)
    {
        var result = await _adminService.GetAuditAsync(new AdminAuditFilter
        {
            UserId = id,
            Page = page,
            PageSize = pageSize,
            Since = since,
            EventId = eventId,
        }, ct);

        return result is null ? NotFound() : Ok(result);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private string GetCurrentAdminId() =>
        User.FindFirst(ClaimConstants.Sub)?.Value ?? string.Empty;

    /// <summary>
    /// Self-protection guard: returns true (and populates the response) when the target id
    /// matches the current admin's id. Destructive endpoints call this first so admins can't
    /// accidentally lock / revoke themselves.
    /// </summary>
    private bool RejectIfSelf(string targetId, out IActionResult response)
    {
        var currentId = GetCurrentAdminId();
        if (string.Equals(targetId, currentId, StringComparison.Ordinal))
        {
            response = BadRequest(new ApiResponse().AddError(
                "self_target",
                "Admins cannot apply destructive operations to their own account via this endpoint."));
            return true;
        }
        response = null!;
        return false;
    }
}
