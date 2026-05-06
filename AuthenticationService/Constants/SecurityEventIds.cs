namespace AuthenticationService.Constants;

/// <summary>
/// Stable <see cref="EventId"/>s for security-relevant events emitted by this service. SIEM
/// rules match on these IDs rather than message strings, so values must not change once
/// deployed — treat them as a wire contract with whatever consumes the logs.
///
/// <para><b>Field-naming conventions</b> for log statements that use these EventIds:</para>
/// <list type="bullet">
///   <item><description><c>{UserId}</c> — the <c>sub</c> claim / <c>User.Id</c>. Empty string when the target user doesn't exist (e.g., login attempt against an unknown email).</description></item>
///   <item><description><c>{IpAddress}</c> — caller's IP via <c>Request.GetRemoteIpAddress()</c>.</description></item>
///   <item><description><c>{Jti}</c> — access-token <c>jti</c> claim, when relevant.</description></item>
///   <item><description><c>{FamilyId}</c> — refresh-token family ID / <c>sid</c> claim, when relevant.</description></item>
///   <item><description><c>{Reason}</c> — short token from <c>LoginFailureReason</c> or <c>RevocationReasons</c>.</description></item>
///   <item><description><c>{Provider}</c> — <c>MfaProviders</c> enum value, when relevant.</description></item>
///   <item><description><c>{Severity}</c> — <c>Severity</c> enum value, when relevant.</description></item>
/// </list>
///
/// <para>Property names use PascalCase. The same field name carries the same meaning across
/// every event — <c>UserId</c> is always the <c>sub</c> claim, <c>FamilyId</c> is always the
/// session/refresh-token family, etc. Don't introduce parallel names for the same concept.</para>
///
/// <para>Email addresses, passwords, tokens, refresh-token values, and authenticator secrets
/// MUST NOT appear in event payloads. Use <c>UserId</c> for forensic correlation; let the
/// platform's separate user store map back to email if an investigator needs it.</para>
///
/// <para><b>EventId ranges:</b></para>
/// <list type="bullet">
///   <item><description><b>1000s</b> — Authentication (login, MFA, refresh, logout)</description></item>
///   <item><description><b>2000s</b> — Registration</description></item>
///   <item><description><b>3000s</b> — Account management</description></item>
///   <item><description><b>4000s</b> — Token state</description></item>
/// </list>
/// </summary>
public static class SecurityEventIds
{
    // 1000s — Authentication
    public static readonly EventId LoginSucceeded = new(1001, nameof(LoginSucceeded));
    public static readonly EventId LoginFailed = new(1002, nameof(LoginFailed));
    public static readonly EventId MfaChallengeIssued = new(1003, nameof(MfaChallengeIssued));
    public static readonly EventId MfaVerified = new(1004, nameof(MfaVerified));
    public static readonly EventId MfaFailed = new(1005, nameof(MfaFailed));
    public static readonly EventId FailedLoginLockoutTriggered = new(1006, nameof(FailedLoginLockoutTriggered));
    public static readonly EventId RefreshTokenRotated = new(1007, nameof(RefreshTokenRotated));
    public static readonly EventId RefreshTokenReuseDetected = new(1008, nameof(RefreshTokenReuseDetected));
    public static readonly EventId LogoutPerDevice = new(1009, nameof(LogoutPerDevice));
    public static readonly EventId LogoutAllDevices = new(1010, nameof(LogoutAllDevices));

    // 2000s — Registration
    public static readonly EventId RegistrationCompleted = new(2001, nameof(RegistrationCompleted));
    public static readonly EventId EmailConfirmed = new(2002, nameof(EmailConfirmed));
    public static readonly EventId EmailConfirmationFailed = new(2003, nameof(EmailConfirmationFailed));

    // 3000s — Account management
    public static readonly EventId PasswordChanged = new(3001, nameof(PasswordChanged));
    public static readonly EventId PasswordResetRequested = new(3002, nameof(PasswordResetRequested));
    public static readonly EventId PasswordResetCompleted = new(3003, nameof(PasswordResetCompleted));
    public static readonly EventId AccountLockedByUser = new(3004, nameof(AccountLockedByUser));
    public static readonly EventId MfaEnabled = new(3005, nameof(MfaEnabled));

    // 4000s — Token state
    public static readonly EventId TokenRevoked = new(4001, nameof(TokenRevoked));
    public static readonly EventId RevokedTokenReplayAttempt = new(4002, nameof(RevokedTokenReplayAttempt));
    public static readonly EventId OrphanedTokenRevoked = new(4003, nameof(OrphanedTokenRevoked));
    public static readonly EventId RevokedTokenReplayThresholdWarned = new(4004, nameof(RevokedTokenReplayThresholdWarned));
    public static readonly EventId RevokedTokenReplayThresholdLocked = new(4005, nameof(RevokedTokenReplayThresholdLocked));
}
