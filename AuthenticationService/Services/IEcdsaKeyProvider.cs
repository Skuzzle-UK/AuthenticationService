using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Services;

/// <summary>
/// Holds the ES256 signing keys the service uses to sign and validate JWTs. Exposes one
/// "active" key for signing new tokens and the full set of public keys for validation,
/// so tokens issued by older keys still validate during a rotation overlap window.
/// </summary>
public interface IEcdsaKeyProvider
{
    /// <summary>
    /// The <c>kid</c> (RFC 7638 thumbprint) of the key currently being used to sign new tokens.
    /// </summary>
    string KeyId { get; }
    /// <summary>
    /// Signing credentials for newly-issued tokens. Always references the active key.
    /// </summary>
    SigningCredentials SigningCredentials { get; }
    /// <summary>
    /// Every public key currently loaded — the active one plus any predecessors still being
    /// honoured. JwtBearer uses the whole list to validate, so a token signed by a
    /// just-rotated-out key still verifies until it's explicitly removed.
    /// </summary>
    IReadOnlyList<SecurityKey> PublicSecurityKeys { get; }

    /// <summary>
    /// Same set of public keys but as JWKs — what <c>/.well-known/jwks.json</c> serves to
    /// consumers so they can validate tokens signed by any active or recently-rotated-out key.
    /// </summary>
    IReadOnlyList<JsonWebKey> PublicJsonWebKeys { get; }
}
