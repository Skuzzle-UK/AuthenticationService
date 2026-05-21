using AuthenticationService.Constants;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthenticationService.Helpers;

/// <summary>
/// Builds the URLs embedded in account emails (password reset, lockout confirmation).
/// </summary>
public static class AccountHelpers
{
    /// <summary>
    /// Link for a password-reset email.
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
    /// "Wasn't me!" link in the password-changed notification — lands on the lockout
    /// endpoint so a hijacked account can be locked down fast.
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
