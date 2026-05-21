namespace AuthenticationService.Constants;

/// <summary>
/// Bundled Razor page paths — used as fallback targets for email links when no
/// consumer-supplied callback URL is configured.
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
    /// Landing page when a flow has nowhere else to redirect to.
    /// </summary>
    public const string ActionComplete = "/ActionComplete";

    /// <summary>
    /// Landing page for admin-invited users to set their initial password.
    /// </summary>
    public const string AcceptInvitation = "/AcceptInvitation";
}