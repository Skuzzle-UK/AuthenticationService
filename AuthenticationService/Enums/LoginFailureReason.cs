namespace AuthenticationService.Enums;

/// <summary>
/// Why a login attempt was rejected. Logged as the <c>{Reason}</c> field on
/// <c>SecurityEventIds.LoginFailed</c> events so SIEM rules can distinguish "wrong password"
/// from "account state prevents login."
/// </summary>
public enum LoginFailureReason
{
    /// <summary>
    /// Wrong username/email or wrong password.
    /// </summary>
    BadCredentials,
    /// <summary>
    /// Account is currently locked (manual lock, or auto-lock from failed attempts).
    /// </summary>
    AccountLocked,
    /// <summary>
    /// Account exists but the email hasn't been confirmed yet.
    /// </summary>
    EmailNotConfirmed,}
