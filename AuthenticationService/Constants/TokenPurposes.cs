namespace AuthenticationService.Constants;

/// <summary>
/// Purpose strings for <c>UserManager.GenerateUserTokenAsync</c> / <c>VerifyUserTokenAsync</c>.
/// Binds a token to a specific flow — a Lockout token won't redeem for password reset.
/// </summary>
public class TokenPurposes
{
    /// <summary>
    /// "Wasn't me!" lock-account flow.
    /// </summary>
    public const string Lockout = "Lockout";
}