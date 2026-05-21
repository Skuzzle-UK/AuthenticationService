using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;

namespace AuthenticationService.Services;

/// <summary>
/// Business logic behind <c>AdminController</c>: list, detail, lock/unlock, session revoke,
/// MFA reset, force-password-reset, and the admin-creates-user invitation flow.
/// <b>Self-protection</b> is the caller's responsibility — destructive operations here will
/// execute against any target including the calling admin. The controller rejects self-target
/// before the call lands.
/// </summary>
public interface IAdminService
{
    Task<PagedResponse<UserSummaryDto>> ListUsersAsync(AdminListFilter filter, CancellationToken ct);

    /// <summary>
    /// Returns null when no user exists with that id.
    /// </summary>
    Task<UserDetailDto?> GetUserDetailAsync(string id, CancellationToken ct);

    /// <summary>
    /// Creates a user via the invitation flow: no password, <c>EmailConfirmed = false</c>,
    /// roles assigned (defaults to <c>DefaultUser</c>; <c>Admin</c> rejected), invitation
    /// email sent.
    /// </summary>
    Task<AdminCreateUserResult> CreateUserAsync(AdminCreateUserDto request, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Re-issues the invitation email if the user is still in the pending-invitation state
    /// (<c>!EmailConfirmed &amp;&amp; PasswordHash IS NULL</c>).
    /// </summary>
    Task<AdminInvitationResendResult> ResendInvitationAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Locks a user account indefinitely. Idempotent.
    /// </summary>
    Task<LockoutInfoDto?> LockUserAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Lifts an active lockout and resets the failed-attempt counter. Idempotent.
    /// </summary>
    Task<LockoutInfoDto?> UnlockUserAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Revokes refresh-token families + rotates security stamp. The "log out everywhere" hammer.
    /// </summary>
    Task<bool> RevokeSessionsAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Disables MFA, clears the authenticator key, and revokes all sessions — if MFA was the
    /// last barrier behind a leaked password, leaving live sessions undoes the protection.
    /// </summary>
    Task<bool> ResetMfaAsync(string targetUserId, string adminUserId, string ipAddress, CancellationToken ct);

    /// <summary>
    /// Generates a password-reset token and emails it to the user. Existing sessions are revoked.
    /// Admin never sees the new password.
    /// </summary>
    Task<bool> ForcePasswordResetAsync(string targetUserId, string adminUserId, string ipAddress, string? callbackUri, CancellationToken ct);

    /// <summary>
    /// Reads from <c>SecurityEvents</c>. Returns null when the user doesn't exist (caller maps to 404).
    /// </summary>
    Task<PagedResponse<AuditEntryDto>?> GetAuditAsync(AdminAuditFilter filter, CancellationToken ct);
}
