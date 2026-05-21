namespace AuthenticationService.Constants;

/// <summary>
/// Canonical revocation reasons. Snake-case so they're stable across renames in code and
/// round-trip cleanly in JSON / log payloads.
/// </summary>
public static class RevocationReasons
{
    /// <summary>
    /// User-initiated logout from a single device.
    /// </summary>
    public const string Logout = "logout";

    /// <summary>
    /// User-initiated logout from all devices.
    /// </summary>
    public const string LogoutAll = "logout_all";

    /// <summary>
    /// User changed their password while authenticated.
    /// </summary>
    public const string PasswordChange = "password_change";

    /// <summary>
    /// User reset a forgotten password via email link.
    /// </summary>
    public const string PasswordReset = "password_reset";

    /// <summary>
    /// User triggered the panic-button lock-account email link.
    /// </summary>
    public const string AccountLock = "account_lock";

    /// <summary>
    /// Account auto-locked after exceeding the failed-login threshold.
    /// </summary>
    public const string FailedLoginLockout = "failed_login_lockout";

    /// <summary>
    /// Cascade revoke triggered by refresh-token reuse detection.
    /// </summary>
    public const string ReuseDetected = "reuse_detected";

    /// <summary>
    /// Token presented for a user that no longer exists.
    /// </summary>
    public const string UserNotFound = "user_not_found";

    public const string AdminRevokedSessions = "admin_revoked_sessions";

    /// <summary>
    /// Defence-in-depth — sessions revoked when admin clears MFA.
    /// </summary>
    public const string AdminResetMfa = "admin_reset_mfa";

    public const string AdminForcedPasswordReset = "admin_forced_password_reset";
}