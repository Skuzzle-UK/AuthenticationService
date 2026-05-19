using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;

namespace AuthenticationService.Services;

/// <summary>
/// Business logic behind the <c>AdminController</c>. Wraps <see cref="IUserService"/>,
/// <see cref="ITokenService"/>, and the EF Core context to provide the admin-flavoured
/// user-management surface: paginated list, full detail, lock / unlock, session revoke,
/// MFA reset, force-password-reset, and the admin-creates-user invitation flow.
///
/// <para>Controllers stay thin — they handle HTTP shape (auth gate, rate-limit attributes,
/// status-code mapping) and delegate everything else here. Mirrors the
/// <c>AccountController</c> → <c>IUserService</c> split that already exists for end-user
/// operations.</para>
///
/// <para><b>Self-protection</b> is the caller's responsibility: destructive operations
/// here will execute against any target including the calling admin. The controller
/// rejects self-target before the call lands.</para>
/// </summary>
public interface IAdminService
{
    /// <summary>
    /// Paginated user list with optional filters. See <see cref="AdminListFilter"/> for
    /// the supported filter shape.
    /// </summary>
    Task<PagedResponse<UserSummaryDto>> ListUsersAsync(AdminListFilter filter, CancellationToken ct);

    /// <summary>
    /// Full detail for a single user. Returns null when no user exists with that id.
    /// </summary>
    Task<UserDetailDto?> GetUserDetailAsync(string id, CancellationToken ct);

    /// <summary>
    /// Creates a new user via the invitation flow:
    /// <list type="number">
    ///   <item><description>Creates the user with no password and <c>EmailConfirmed = false</c>.</description></item>
    ///   <item><description>Assigns roles (defaults to <c>DefaultUser</c>; <c>Admin</c> rejected).</description></item>
    ///   <item><description>Generates an Identity password-reset token + sends the invitation email.</description></item>
    /// </list>
    /// On failure the result carries Identity / validation errors; on success it carries the new user's id.
    /// </summary>
    Task<AdminCreateUserResult> CreateUserAsync(AdminCreateUserDto request, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Re-issues the invitation email for a user still in the pending-invitation state
    /// (<c>!EmailConfirmed &amp;&amp; PasswordHash IS NULL</c>). Returns
    /// <see cref="AdminInvitationResendResult.UserNotFound"/> / <see cref="AdminInvitationResendResult.UserAlreadyActive"/>
    /// on the obvious negative paths.
    /// </summary>
    Task<AdminInvitationResendResult> ResendInvitationAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Locks a user account indefinitely. Idempotent — calling on an already-locked account refreshes the timestamp.
    /// </summary>
    Task<LockoutInfoDto?> LockUserAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Lifts an active lockout and resets the failed-attempt counter. Idempotent.
    /// </summary>
    Task<LockoutInfoDto?> UnlockUserAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Revokes all refresh-token families + rotates security stamp + revokes the current admin's access token if presented. The "log them out everywhere" hammer.
    /// </summary>
    Task<bool> RevokeSessionsAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Disables MFA + clears the authenticator key + revokes all sessions for the user (defence in depth — if MFA was the only barrier behind a leaked password, leaving live sessions is worse than nothing).
    /// </summary>
    Task<bool> ResetMfaAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Generates a password-reset token + emails it to the user. Existing sessions
    /// are revoked. Reuses the same flow as the user's own forgot-password — admin never
    /// sees the new password.
    /// </summary>
    Task<bool> ForcePasswordResetAsync(string targetUserId, string adminUserId, string ipAddress, string? callbackUri, CancellationToken ct);

    /// <summary>
    /// Paginated audit log for the user — reads from the <c>SecurityEvents</c> table
    /// populated by <c>SecurityEventSink</c>. Returns null when the user doesn't exist
    /// so the caller can map that to a 404; an empty page is returned for an existing
    /// user with no events in the window.
    /// </summary>
    Task<PagedResponse<AuditEntryDto>?> GetAuditAsync(AdminAuditFilter filter, CancellationToken ct);
}
