using Microsoft.AspNetCore.WebUtilities;

namespace AuthenticationService.Helpers;

public static class AccountHelpers
{
    public static string GenerateResetPasswordUri(string email, string token, string callbackUri)
    {
        var resetPasswordParams = new Dictionary<string, string>
        {
            { "token", token },
            { "email", email }
        };

        return QueryHelpers.AddQueryString(callbackUri, resetPasswordParams!);
    }

    public static string GenerateLockoutUri(string email, string token, string callbackUri)
    {
        var lockoutParams = new Dictionary<string, string>
        {
            { "token", token },
            { "email", email },
            { "lockout", "true" }
        };

        return QueryHelpers.AddQueryString(callbackUri, lockoutParams!);
    }
}
