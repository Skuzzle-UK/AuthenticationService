namespace AuthenticationService.Constants;

/// <summary>
/// Canonical reasons recorded against revoked tokens (both access tokens in <c>RevokedTokens</c>
/// and refresh tokens in <c>RefreshTokens</c>). Snake-case strings so they're stable across
/// renames in code and round-trip cleanly in JSON / log payloads.
/// </summary>
public static class RevocationReasons
{
    /// <summary>User-initiated logout from a single device.</summary>
    public const string Logout = "logout";

    /// <summary>User-initiated logout from all devices.</summary>
    public const string LogoutAll = "logout_all";

    /// <summary>User changed their password while authenticated.</summary>
    public const string PasswordChange = "password_change";

    /// <summary>User reset a forgotten password via email link.</summary>
    public const string PasswordReset = "password_reset";

    /// <summary>User triggered the panic-button lock-account email link.</summary>
    public const string AccountLock = "account_lock";

    /// <summary>Account auto-locked after exceeding the failed-login threshold.</summary>
    public const string FailedLoginLockout = "failed_login_lockout";

    /// <summary>Refresh-token reuse detected; cascade revoked all the user's tokens.</summary>
    public const string ReuseDetected = "reuse_detected";
}
