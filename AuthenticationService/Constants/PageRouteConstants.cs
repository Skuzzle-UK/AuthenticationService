namespace AuthenticationService.Constants;

/// <summary>
/// Paths to the bundled Razor pages this service ships. Used when building email links
/// that point users at the auth service's own UI as a fallback (when no consumer-supplied
/// callback URL is available).
/// </summary>
public class PageRouteConstants
{
    /// <summary>
    /// The "set a new password" page, hit from password-reset email links.
    /// </summary>
    public const string ResetPassword = "/ResetPassword";

    /// <summary>
    /// The "lock my account" page, hit from the panic-button link in password-changed emails.
    /// </summary>
    public const string LockAccount = "/LockAccount";

    /// <summary>
    /// Generic "your action completed" landing page — shown when a flow has nowhere else to redirect to.
    /// </summary>
    public const string ActionComplete = "/ActionComplete";
}