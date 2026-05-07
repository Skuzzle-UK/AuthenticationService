using AuthenticationService.Constants;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthenticationService.Helpers;

/// <summary>
/// Builds the URLs that get embedded in account-related emails (password reset, lockout
/// confirmation). Just appends the right query-string params to the supplied callback URL.
/// </summary>
public static class AccountHelpers
{
    /// <summary>
    /// Builds the link sent in a password-reset email.
    /// </summary>
    public static string GenerateResetPasswordUri(string email, string token, string callbackUri)
    {
        var resetPasswordParams = new Dictionary<string, string>
        {
            { UriConstants.Token, token },
            { UriConstants.Email, email }
        };

        return QueryHelpers.AddQueryString(callbackUri, resetPasswordParams!);
    }

    /// <summary>
    /// Builds the "wasn't me!" link sent in the password-changed notification, which lands
    /// the recipient on the lockout endpoint so a hijacked account can be locked down fast.
    /// </summary>
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
