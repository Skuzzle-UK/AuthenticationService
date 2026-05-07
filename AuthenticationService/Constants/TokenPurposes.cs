namespace AuthenticationService.Constants;

/// <summary>
/// Purpose strings passed to ASP.NET Core Identity's
/// <c>UserManager.GenerateUserTokenAsync</c> / <c>VerifyUserTokenAsync</c> when generating
/// custom email-link tokens. The purpose binds the token to a specific flow — a token
/// generated for "Lockout" can't be redeemed for password reset and vice versa.
/// </summary>
public class TokenPurposes
{
    /// <summary>
    /// Used by the panic-button "wasn't me!" lock-account flow.
    /// </summary>
    public const string Lockout = "Lockout";
}