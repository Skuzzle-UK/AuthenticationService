using AuthenticationService.Constants;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthenticationService.Helpers;

public static class AccountHelpers
{
    public static string GenerateResetPasswordUri(string email, string token, string callbackUri)
    {
        var resetPasswordParams = new Dictionary<string, string>
        {
            { UriConstants.Token, token },
            { UriConstants.Email, email }
        };

        return QueryHelpers.AddQueryString(callbackUri, resetPasswordParams!);
    }

    public static string GenerateLockoutUri(string email, string token, string callbackUri)
    {
        var lockoutParams = new Dictionary<string, string>
        {
            { UriConstants.Token, token },
            { UriConstants.Email, email },
            { UriConstants.Lockout, UriConstants.True }
        };

        return QueryHelpers.AddQueryString(callbackUri, lockoutParams!);
    }
}
