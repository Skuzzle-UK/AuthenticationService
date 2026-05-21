namespace AuthenticationService.Constants;

/// <summary>
/// Subject lines for outbound emails.
/// </summary>
public class EmailSubjects
{
    public const string PasswordReset = "Password Reset";

    /// <summary>
    /// Carries the "wasn't you?" panic-button link.
    /// </summary>
    public const string PasswordChanged = "Password Changed";

    /// <summary>
    /// Email-confirmation link sent after registration.
    /// </summary>
    public const string EmailConfirmation = "Email Confirmation";

    /// <summary>
    /// One-time MFA challenge code sent during the login flow.
    /// </summary>
    public const string MfaAuthenticationToken = "MFA Authentication Token";

    /// <summary>
    /// Auto-clearing lockout after failed-login threshold; informational framing.
    /// </summary>
    public const string LockedAccountInfo = "Locked account information";

    /// <summary>
    /// User-triggered panic-button lock (indefinite).
    /// </summary>
    public const string AccountLocked = "Account Locked";

    /// <summary>
    /// Server-initiated lock — refresh-token reuse or threshold-escalation. Must reset to recover.
    /// </summary>
    public const string SuspiciousActivity = "Suspicious activity detected on your account";

    /// <summary>
    /// Admin-invitation email — initial creation or resend.
    /// </summary>
    public const string AccountInvitation = "Account invitation - set your password";
}
