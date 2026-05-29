using AuthenticationService.Constants;
using AuthenticationService.Extensions;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Controllers;

/// <summary>
/// Admin user + client management. All actions require <see cref="PolicyConstants.AdminOnly"/>. Destructive actions refuse self-target so admins can't lock themselves out.
/// </summary>
[Route("api/[controller]")]
[ApiController]
[Authorize(Policy = PolicyConstants.AdminOnly)]
[EnableRateLimiting(RateLimitPolicies.AuthSensitive)]
public class AdminController : ControllerBase
{
    private readonly IAdminService _adminService;
    private readonly IClientService _clientService;
    private readonly Storage.DatabaseContext _db;
    private readonly ILogger<AdminController> _logger;

    public AdminController(
        IAdminService adminService,
        IClientService clientService,
        Storage.DatabaseContext db,
        ILogger<AdminController> logger)
    {
        _adminService = adminService;
        _clientService = clientService;
        _db = db;
        _logger = logger;
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
    /// Full detail for a single user — profile, lockout, MFA, roles, active session count.
    /// </summary>
    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUserAsync(string id, CancellationToken ct)
    {
        var detail = await _adminService.GetUserDetailAsync(id, ct);
        return detail is null ? NotFound() : Ok(detail);
    }

    /// <summary>
    /// Creates a user via the invitation flow. Account is unusable until the user clicks the email link and sets a password.
    /// </summary>
    [HttpPost("users")]
    public async Task<IActionResult> CreateUserAsync(
        [FromBody] AdminCreateUserDto request,
        CancellationToken ct)
    {
        var result = await _adminService.CreateUserAsync(
            request,
            callerUserId: User.GetUserIdOrEmpty(),
            callerRoles: User.GetRoles(),
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
    /// Re-sends the invitation email. Returns 409 if the user has already activated their account.
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
            callerUserId: User.GetUserIdOrEmpty(),
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
            callerUserId: User.GetUserIdOrEmpty(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return info is null ? NotFound() : Ok(info);
    }

    /// <summary>
    /// Lifts an active lockout and resets the failed-attempt counter. Refuses self-target (admins use the seed-account recovery path).
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
            callerUserId: User.GetUserIdOrEmpty(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return info is null ? NotFound() : Ok(info);
    }

    /// <summary>
    /// Revokes every active session — refresh-token families + rotates security stamp. Doesn't lock the account; user can sign back in.
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
            callerUserId: User.GetUserIdOrEmpty(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return ok ? Ok(new ApiResponse()) : NotFound();
    }

    /// <summary>
    /// Disables MFA and clears the authenticator key — helpdesk lost-phone recovery. Revokes all sessions implicitly.
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
            callerUserId: User.GetUserIdOrEmpty(),
            ipAddress: Request.GetRemoteIpAddress(),
            ct);

        return ok ? Ok(new ApiResponse()) : NotFound();
    }

    /// <summary>
    /// Generates a reset token, emails it, and revokes existing sessions. Admin never sees the new password.
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
            callerUserId: User.GetUserIdOrEmpty(),
            ipAddress: Request.GetRemoteIpAddress(),
            callbackUri: request?.CallbackUri,
            ct);

        return ok ? Ok(new ApiResponse()) : NotFound();
    }

    public sealed class ForcePasswordResetRequest
    {
        public string? CallbackUri { get; set; }
    }

    /// <summary>
    /// Paginated audit log for the user. Reads <c>SecurityEvents</c>; defaults to the last 30 days.
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

    // Self-protection guard for destructive endpoints — returns true (with response) when targetId matches the current admin.
    private bool RejectIfSelf(string targetId, out IActionResult response)
    {
        var currentId = User.GetUserIdOrEmpty();
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

    // ────────────────────────────────────────────────────────────────────────────────
    // OAuth client management (s2s) — see docs/service-to-service-auth-plan.md Phase 1
    // ────────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a new OAuth client. Plaintext secret is returned <em>once</em> in the response — only the hash is persisted.
    /// </summary>
    [HttpPost("clients")]
    public async Task<IActionResult> CreateClientAsync(
        [FromBody] AdminCreateClientDto request,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Id) || string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new ApiResponse().AddError("validation", "Id and Name are required."));
        }

        var scopes = (request.Scopes ?? [])
            .Where(s => !string.IsNullOrWhiteSpace(s.Audience) && !string.IsNullOrWhiteSpace(s.Scope))
            .Select(s => (s.Audience!, s.Scope!))
            .ToList();

        var rawSecret = GenerateSecret();
        var client = await _clientService.CreateAsync(request.Id, request.Name, rawSecret, request.Description, scopes, ct);

        _logger.LogInformation(
            SecurityEventIds.AdminCreatedClient,
            "Admin {CallerUserId} created client {ClientId} with {ScopeCount} scopes from {IpAddress}",
            User.GetUserIdOrEmpty(),
            client.Id,
            scopes.Count,
            Request.GetRemoteIpAddress());

        var response = new ClientCreatedResponse
        {
            Id = client.Id,
            Name = client.Name,
            ClientSecret = rawSecret,
        };
        return Created($"/api/Admin/clients/{client.Id}", response);
    }

    /// <summary>
    /// Paginated list of clients with optional <c>activeOnly</c> filter.
    /// </summary>
    [HttpGet("clients")]
    public async Task<IActionResult> ListClientsAsync(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = AdminListFilter.DefaultPageSize,
        [FromQuery] bool activeOnly = false,
        CancellationToken ct = default)
    {
        var p = Math.Max(1, page);
        var ps = Math.Clamp(pageSize, 1, AdminListFilter.MaxPageSize);

        var query = _db.Clients.AsNoTracking();
        if (activeOnly)
        {
            query = query.Where(c => !c.IsDisabled);
        }

        var totalCount = await query.CountAsync(ct);
        var results = await query
            .OrderByDescending(c => c.CreatedAt)
            .Skip((p - 1) * ps)
            .Take(ps)
            .Select(c => new ClientSummaryDto
            {
                Id = c.Id,
                Name = c.Name,
                IsDisabled = c.IsDisabled,
                CreatedAt = c.CreatedAt,
                LastUsedAt = c.LastUsedAt,
                Description = c.Description,
            })
            .ToListAsync(ct);

        return Ok(new PagedResponse<ClientSummaryDto>
        {
            Results = results,
            TotalCount = totalCount,
            Page = p,
            PageSize = ps,
        });
    }

    /// <summary>
    /// Full detail for a single client — metadata + scopes list. Never includes the secret hash.
    /// </summary>
    [HttpGet("clients/{id}")]
    public async Task<IActionResult> GetClientAsync(string id, CancellationToken ct)
    {
        var client = await _db.Clients
            .AsNoTracking()
            .Include(c => c.Scopes)
            .FirstOrDefaultAsync(c => c.Id == id, ct);

        if (client is null)
        {
            return NotFound();
        }

        return Ok(new ClientDetailDto
        {
            Id = client.Id,
            Name = client.Name,
            IsDisabled = client.IsDisabled,
            CreatedAt = client.CreatedAt,
            LastUsedAt = client.LastUsedAt,
            Description = client.Description,
            Scopes = [.. client.Scopes.Select(s => new AdminClientScopeDto { Audience = s.Audience, Scope = s.Scope })],
        });
    }

    /// <summary>
    /// Generates a fresh secret and overwrites the stored hash. Response carries the new plaintext — same one-time-display contract as create.
    /// </summary>
    [HttpPost("clients/{id}/rotate-secret")]
    public async Task<IActionResult> RotateClientSecretAsync(string id, CancellationToken ct)
    {
        var rawSecret = GenerateSecret();
        var client = await _clientService.RotateSecretAsync(id, rawSecret, ct);
        if (client is null)
        {
            return NotFound();
        }

        _logger.LogWarning(
            SecurityEventIds.AdminRotatedClientSecret,
            "Admin {CallerUserId} rotated secret for client {ClientId} from {IpAddress}",
            User.GetUserIdOrEmpty(),
            client.Id,
            Request.GetRemoteIpAddress());

        return Ok(new ClientCreatedResponse
        {
            Id = client.Id,
            Name = client.Name,
            ClientSecret = rawSecret,
        });
    }

    /// <summary>
    /// Soft-disable the client. Subsequent /oauth/token attempts return invalid_client. Idempotent.
    /// </summary>
    [HttpPost("clients/{id}/disable")]
    public async Task<IActionResult> DisableClientAsync(string id, CancellationToken ct)
    {
        var changed = await _clientService.DisableAsync(id, ct);
        if (!changed)
        {
            // Differentiate "no such client" vs "already disabled" so admin tooling can give a precise message.
            var exists = await _db.Clients.AsNoTracking().AnyAsync(c => c.Id == id, ct);
            return exists ? Ok(new ApiResponse()) : NotFound();
        }

        _logger.LogWarning(
            SecurityEventIds.AdminDisabledClient,
            "Admin {CallerUserId} disabled client {ClientId} from {IpAddress}",
            User.GetUserIdOrEmpty(),
            id,
            Request.GetRemoteIpAddress());

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Add an (audience, scope) tuple to a client. Idempotent.
    /// </summary>
    [HttpPost("clients/{id}/scopes")]
    public async Task<IActionResult> AddClientScopeAsync(
        string id,
        [FromBody] AdminClientScopeDto request,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Audience) || string.IsNullOrWhiteSpace(request.Scope))
        {
            return BadRequest(new ApiResponse().AddError("validation", "Audience and Scope are required."));
        }

        var added = await _clientService.AddScopeAsync(id, request.Audience, request.Scope, ct);
        if (added)
        {
            _logger.LogInformation(
                SecurityEventIds.AdminAddedClientScope,
                "Admin {CallerUserId} added scope {Audience}/{Scope} to client {ClientId} from {IpAddress}",
                User.GetUserIdOrEmpty(),
                request.Audience,
                request.Scope,
                id,
                Request.GetRemoteIpAddress());
        }

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Remove a (audience, scope) tuple from a client. Returns 404 if the tuple wasn't present.
    /// </summary>
    [HttpDelete("clients/{id}/scopes/{audience}/{scope}")]
    public async Task<IActionResult> RemoveClientScopeAsync(
        string id,
        string audience,
        string scope,
        CancellationToken ct)
    {
        var removed = await _clientService.RemoveScopeAsync(id, audience, scope, ct);
        if (!removed)
        {
            return NotFound();
        }

        _logger.LogWarning(
            SecurityEventIds.AdminRemovedClientScope,
            "Admin {CallerUserId} removed scope {Audience}/{Scope} from client {ClientId} from {IpAddress}",
            User.GetUserIdOrEmpty(),
            audience,
            scope,
            id,
            Request.GetRemoteIpAddress());

        return Ok(new ApiResponse());
    }

    // 32 bytes / 256 bits → 43 chars Base64URL. Brute-force infeasible, short enough to paste without line-folding.
    private static string GenerateSecret()
    {
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(bytes);
    }
}
