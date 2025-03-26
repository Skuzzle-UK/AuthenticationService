using AuthenticationService.Shared.Enums;
using AuthenticationService.Shared.Models;

namespace AuthenticationService.Shared.Dtos.Response;

public class AuthenticationResponse : ApiResponse
{
    public Token? Token { get; set; }
    public bool? MfaRequired { get; set; }
    public string? MfaProvider { get; set; }

    /// <summary>
    /// Returns new AuthenticationResponse with token.
    /// </summary>
    /// <param name="token"></param>
    public static AuthenticationResponse WithToken(Token? token)
    {
        return new AuthenticationResponse()
        {
            Token = token
        };
    }


    /// <summary>
    /// Returns new AuthenticationResponse with MFA required set to true and proferred mfa provider.
    /// </summary>
    /// <param name="mfaProvider"></param>
    /// <returns></returns>
    public static AuthenticationResponse WithMfaRequired(MfaProviders? mfaProvider)
    {
        return new AuthenticationResponse()
        {
            MfaRequired = true,
            MfaProvider = mfaProvider.ToString()
        };
    }
}
