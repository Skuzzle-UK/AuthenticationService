using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Services;

public interface IEcdsaKeyProvider
{
    string KeyId { get; }
    SigningCredentials SigningCredentials { get; }
    SecurityKey PublicSecurityKey { get; }
    JsonWebKey PublicJsonWebKey { get; }
}
