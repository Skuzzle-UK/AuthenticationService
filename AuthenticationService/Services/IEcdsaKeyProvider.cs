using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Services;

public interface IEcdsaKeyProvider
{
    /// <summary>Thumbprint of the active signing key.</summary>
    string KeyId { get; }

    /// <summary>Credentials for signing newly-issued tokens. Always uses the active key.</summary>
    SigningCredentials SigningCredentials { get; }

    /// <summary>
    /// Every loaded public key — active and any other keys present in the directory.
    /// JwtBearer uses the full set for validation so tokens signed by any present key
    /// (e.g. just-rotated-out predecessors) still validate during the overlap window.
    /// </summary>
    IReadOnlyList<SecurityKey> PublicSecurityKeys { get; }

    /// <summary>
    /// JWK representation of every loaded key. The <c>/.well-known/jwks.json</c> endpoint
    /// returns this list verbatim so consumers can validate against any active or
    /// recently-rotated-out key.
    /// </summary>
    IReadOnlyList<JsonWebKey> PublicJsonWebKeys { get; }
}
