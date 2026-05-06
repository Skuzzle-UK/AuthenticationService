using AuthenticationService.Entities;
using AuthenticationService.Shared.Models;

namespace AuthenticationService.Services;

/// <summary>
/// Issues, validates, rotates and revokes JWT access tokens and their paired refresh tokens.
/// All token logic lives behind this interface — controllers never touch JWT plumbing directly.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Creates a fresh access token + refresh token pair for the given user.
    /// Pass <paramref name="familyId"/> to keep the new pair in an existing refresh-token
    /// family (used during rotation); leave it null on a fresh login so a new family is started.
    /// <paramref name="ipAddress"/> is recorded against the refresh token for audit.
    /// </summary>
    Task<Token> CreateTokenAsync(User user, IList<string> roles, Guid? familyId = null, string? ipAddress = null);

    /// <summary>
    /// Validates a token's signature, issuer and audience but ignores its expiry. Used during
    /// the refresh flow where we expect the access token to have already expired.
    /// </summary>
    Task<bool> ValidateExpiredTokenAsync(string token);

    /// <summary>
    /// Adds the access token's <c>jti</c> to the revoked-token list so any future presentation
    /// is rejected. <paramref name="reason"/> is stored for audit (see <c>RevocationReasons</c>).
    /// </summary>
    Task RevokeTokenAsync(string token, string ipAddress, string reason);

    /// <summary>
    /// The refresh flow: validates the supplied refresh token, marks it consumed, and issues
    /// a fresh access + refresh pair in the same family.
    ///
    /// <para>If the same refresh token is presented a second time we treat it as theft —
    /// every active session for the user is revoked and the security stamp is rotated before
    /// this method returns. Inspect the returned <see cref="RefreshResult"/> to know which
    /// path was taken (success, expired, not-found, or reuse-detected).</para>
    /// </summary>
    Task<RefreshResult> RotateRefreshTokenAsync(string accessToken, string rawRefreshToken, string ipAddress);

    /// <summary>
    /// Revokes every active refresh token the user holds — the "log out everywhere" hammer.
    /// Used by reuse-detection, password change/reset, lockout, and the explicit
    /// <c>/logoutall</c> endpoint. Does not touch the security stamp; the caller decides
    /// whether to rotate it as well.
    /// </summary>
    Task RevokeAllRefreshTokenFamiliesAsync(string userId, string reason);

    /// <summary>
    /// Revokes every refresh token in a single family — i.e. signs out the one device the
    /// caller is currently using. Other devices keep their sessions. Used by
    /// <c>/logout</c>. Does not touch the security stamp.
    /// </summary>
    Task RevokeFamilyAsync(Guid familyId, string reason);

    /// <summary>
    /// Reads the <c>exp</c> claim from a JWT and returns it as a <see cref="DateTime"/>.
    /// </summary>
    DateTime? GetExpiryDateTime(string token);

    /// <summary>
    /// Reads the <c>sub</c> claim (the stable user id) from a JWT.
    /// </summary>
    string GetUserId(string token);

    /// <summary>
    /// True if the token's <c>jti</c> appears in the revoked-token list.
    /// </summary>
    Task<bool> IsRevokedAsync(string token);

    /// <summary>
    /// Records that someone presented this token. Used by the revoked-token middleware to
    /// log replay attempts of already-revoked tokens for SIEM forwarding.
    /// </summary>
    Task RecordAccessAttemptAsync(string token, string ipAddress);
}
