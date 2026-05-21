using AuthenticationService.Shared.Enums;
using AuthenticationService.Shared.Models;

namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Response from the login and MFA endpoints. Either carries a <see cref="Token"/> or
/// signals that MFA is required next.
/// </summary>
public class AuthenticationResponse : ApiResponse
{
    /// <summary>
    /// Issued access + refresh token pair. Null when MFA is still pending.
    /// </summary>
    public Token? Token { get; set; }

    /// <summary>
    /// True if the user must complete an MFA challenge before getting a token.
    /// </summary>
    public bool? MfaRequired { get; set; }

    /// <summary>
    /// Which MFA provider the client should prompt for.
    /// </summary>
    public MfaProviders? MfaProvider { get; set; }

    /// <summary>
    /// Builds a successful response carrying the issued token pair.
    /// </summary>
    public static AuthenticationResponse WithToken(Token? token)    {
        return new AuthenticationResponse()
        {
            Token = token
        };
    }

    /// <summary>
    /// Builds a "needs MFA" response naming the provider the client should challenge against.
    /// </summary>
    public static AuthenticationResponse WithMfaRequired(MfaProviders? mfaProvider)
    {
        return new AuthenticationResponse()
        {
            MfaRequired = true,
            MfaProvider = mfaProvider
        };
    }
}
