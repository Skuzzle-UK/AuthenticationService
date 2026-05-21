using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Services;

/// <summary>
/// Holds the ES256 signing keys. Exposes one active key for signing new tokens and the
/// full set of public keys for validation so tokens from a just-rotated-out key still verify.
/// </summary>
public interface IEcdsaKeyProvider
{
    /// <summary>
    /// <c>kid</c> (RFC 7638 thumbprint) of the active signing key.
    /// </summary>
    string KeyId { get; }

    /// <summary>
    /// Signing credentials for new tokens. Always references the active key.
    /// </summary>
    SigningCredentials SigningCredentials { get; }

    /// <summary>
    /// All public keys currently loaded — active plus predecessors still being honoured.
    /// JwtBearer validates against the whole list.
    /// </summary>
    IReadOnlyList<SecurityKey> PublicSecurityKeys { get; }

    /// <summary>
    /// Same set as <see cref="PublicSecurityKeys"/> but as JWKs for the discovery endpoint.
    /// </summary>
    IReadOnlyList<JsonWebKey> PublicJsonWebKeys { get; }

    /// <summary>
    /// Pre-built JWKS payload — allocated once at startup and reused on every request.
    /// </summary>
    JwksDocument JwksDocument { get; }
}
