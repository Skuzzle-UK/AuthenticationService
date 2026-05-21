using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Shared.Models;

namespace AuthenticationService.Services;


/// <summary>
/// Issues, validates, rotates and revokes JWT access tokens and their refresh-token pairs.
/// Controllers never touch JWT plumbing directly.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Creates an access + refresh token pair. Pass <paramref name="familyId"/> to extend an
    /// existing family during rotation; leave null on fresh login to start a new family.
    /// <paramref name="refreshTokenId"/> lets rotation pre-allocate the new row's PK so it
    /// can be stamped into the predecessor's <c>ReplacedByTokenId</c> in one UPDATE.
    /// </summary>
    Task<Token> CreateTokenAsync(
        User user,
        IList<string> roles,
        Guid? familyId = null,
        string? ipAddress = null,
        Guid? refreshTokenId = null);

    /// <summary>
    /// Issues a service-identity JWT for OAuth client-credentials. No refresh pair, no user
    /// claims, per-service <paramref name="audience"/>, space-separated <c>scope</c> claim.
    /// Distinguishable from user tokens by absent <c>email</c>/<c>sid</c> claims and by
    /// <c>sub</c> being a client_id.
    /// </summary>
    Task<Token> CreateServiceTokenAsync(string clientId, string audience, IEnumerable<string> scopes);

    /// <summary>
    /// Validates signature, issuer and audience but ignores expiry. Used during refresh.
    /// </summary>
    Task<bool> ValidateExpiredTokenAsync(string token);

    /// <summary>
    /// Adds the token's <c>jti</c> to the revoked-token deny-list.
    /// </summary>
    Task RevokeTokenAsync(string token, string ipAddress, string reason);

    /// <summary>
    /// Revokes a token whose user no longer exists. Emits Warning-level
    /// <see cref="SecurityEventIds.OrphanedTokenRevoked"/> for SIEM.
    /// </summary>
    Task RevokeOrphanedTokenAsync(string token, string ipAddress);

    /// <summary>
    /// Refresh flow with reuse detection. If a token is presented a second time we treat it
    /// as theft — all families for the user are revoked and the security stamp rotated before
    /// returning. Inspect <see cref="RefreshResult"/> for the path taken.
    /// </summary>
    Task<RefreshResult> RotateRefreshTokenAsync(string accessToken, string rawRefreshToken, string ipAddress);

    /// <summary>
    /// "Log out everywhere" hammer. Used by reuse-detection, password change/reset, lockout,
    /// and <c>/logoutall</c>. Does NOT touch the security stamp — caller decides.
    /// </summary>
    Task RevokeAllRefreshTokenFamiliesAsync(string userId, string reason);

    /// <summary>
    /// Signs out one device (single family) — other devices keep their sessions. Used by
    /// <c>/logout</c>. Does not touch the security stamp.
    /// </summary>
    Task RevokeFamilyAsync(Guid familyId, string reason);

    /// <summary>
    /// Reads the <c>exp</c> claim from a JWT and returns it as a <see cref="DateTime"/>.
    /// </summary>
    DateTime? GetExpiryDateTime(string token);

    /// <summary>
    /// Reads the <c>sub</c> claim.
    /// </summary>
    string GetUserId(string token);

    /// <summary>
    /// Returns null if not revoked. Caller can pass the row to <see cref="RecordRevokedReplayAsync"/>
    /// to avoid a second DB lookup.
    /// </summary>
    Task<RevokedToken?> GetRevokedTokenAsync(string token);

    /// <summary>
    /// Records a revoked-token replay for the threshold-escalation worker and SIEM.
    /// <paramref name="userAgent"/> captured so SIEM can correlate replays without ingesting logs.
    /// </summary>
    Task RecordRevokedReplayAsync(RevokedToken revokedToken, string ipAddress, string? userAgent);
}
