using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AuthenticationService.Shared.Models;

namespace AuthenticationService.Services;

public interface ITokenService
{
    /// <summary>
    /// Issues a new access + refresh token pair. Pass <paramref name="familyId"/> to keep
    /// the issued token within an existing refresh-token family (rotation flow); leave
    /// null for fresh logins where a new family should be created. <paramref name="ipAddress"/>
    /// is recorded on the refresh-token row for audit.
    /// </summary>
    Task<Token> CreateTokenAsync(User user, IList<string> roles, Guid? familyId = null, string? ipAddress = null);

    Task<bool> ValidateExpiredTokenAsync(string token);

    Task RevokeTokenAsync(string token, string ipAddress, string reason);

    /// <summary>
    /// Validates a refresh token, marks it consumed, issues a new pair in the same family.
    /// Returns a <see cref="RefreshResult"/> describing the outcome (success, expired,
    /// not-found, or reuse-detected). On reuse-detection the cascade (revoke all families
    /// + rotate security stamp) has already run by the time this returns.
    /// </summary>
    Task<RefreshResult> RotateRefreshTokenAsync(string accessToken, string rawRefreshToken, string ipAddress);

    /// <summary>
    /// Marks every active refresh-token row for the user as consumed with the supplied
    /// reason. Used by reuse-detection, password-change/reset, lockout, and logout-all.
    /// Does not rotate the security stamp; caller decides whether to.
    /// </summary>
    Task RevokeAllRefreshTokenFamiliesAsync(string userId, string reason);

    /// <summary>
    /// Marks every active refresh-token row in a single family as consumed with the supplied
    /// reason. Used by per-device logout. Does not affect other families (other devices) or
    /// rotate the security stamp.
    /// </summary>
    Task RevokeFamilyAsync(Guid familyId, string reason);

    DateTime? GetExpiryDateTime(string token);

    string GetUserId(string token);

    Task<bool> IsRevokedAsync(string token);

    /// <summary>
    /// Records an access attempt. This method can be used for recording legitimate or revoked access attempts.
    /// </summary>
    Task RecordAccessAttemptAsync(string token, string ipAddress);
}
