namespace AuthenticationService.Constants;

/// <summary>
/// Subject lines for outbound emails. Centralised here so each subject only appears once
/// in the codebase — easier to find / change for branding or localisation.
/// </summary>
public class EmailSubjects
{
    /// <summary>
    /// "Forgot password" email — the user-initiated password-reset link.
    /// </summary>
    public const string PasswordReset = "Password Reset";

    /// <summary>
    /// Notification sent after a successful password change. Carries the "wasn't you?" panic-button link.
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
    /// Failed-login-lockout email. Auto-clearing lockout after too many bad passwords —
    /// the user can self-recover by waiting. Framing is informational ("you've been
    /// locked, here's a reset link if you didn't recognise the attempts").
    /// </summary>
    public const string LockedAccountInfo = "Locked account information";

    /// <summary>
    /// User-triggered panic-button lock — sent after the user clicks the "wasn't me!"
    /// link in a password-changed email. The lock is indefinite; the email contains a
    /// reset link so they can recover.
    /// </summary>
    public const string AccountLocked = "Account Locked";

    /// <summary>
    /// Server-initiated lock cascade — refresh-token reuse detected, or the threshold-
    /// escalation worker's indefinite lock. Framing is "we believe your session is
    /// compromised; you must reset your password to recover."
    /// </summary>
    public const string SuspiciousActivity = "Suspicious activity detected on your account";

    /// <summary>
    /// Admin-creates-user invitation — sent on admin user creation, and again on
    /// resend-invitation. Carries the AcceptInvitation link for the user to set their
    /// initial password.
    /// </summary>
    public const string AccountInvitation = "Account invitation - set your password";
}
