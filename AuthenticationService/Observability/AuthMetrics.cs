using System.Diagnostics.Metrics;
using AuthenticationService.Enums;
using AuthenticationService.Shared.Enums;

namespace AuthenticationService.Observability;

/// <summary>
/// Custom business metrics. Singleton; tags are bounded enums/short strings only —
/// user IDs, IPs, and JTIs go to logs/traces, never tags.
/// <see cref="MeterName"/> must match the <c>metrics.AddMeter</c> registration in
/// ServiceDefaults.Extensions.
/// </summary>
public sealed class AuthMetrics
{
    public const string MeterName = "AuthenticationService";

    // Counter EventId references map to SecurityEventIds.cs.
    private readonly Counter<long> _logins;                  // 1001 / 1002
    private readonly Counter<long> _mfaChallenges;           // 1003
    private readonly Counter<long> _mfaVerifications;        // 1004 / 1005
    private readonly Counter<long> _refreshes;               // 1007
    private readonly Counter<long> _refreshReuseDetected;    // 1008 — alert-worthy on its own
    private readonly Counter<long> _registrations;           // 2001 / 2002
    private readonly Counter<long> _lockouts;                // 1006, 3004, 4005
    private readonly Counter<long> _passwordChanges;         // 3001
    private readonly Counter<long> _passwordResets;          // 3002 / 3003
    private readonly Counter<long> _mfaEnabled;              // 3005 — enable events; total via gauge
    private readonly Counter<long> _tokensRevoked;           // 4001
    private readonly Counter<long> _revokedTokenReplays;     // 4002
    private readonly Counter<long> _thresholdEscalations;    // 4004 / 4005
    private readonly Counter<long> _clientCredentialsTokens; // 6001 / 6002

    // Refreshed by UserGaugeRefreshService. Volatile pairs the SDK collection thread
    // with the refresh thread.
    private long _totalUsers;
    private long _mfaEnabledUsers;
    private long _lockedUsers;

    public AuthMetrics(IMeterFactory meterFactory)
    {
        var m = meterFactory.Create(MeterName);

        _logins = m.CreateCounter<long>(
            name: "auth.logins.total",
            description: "Login attempts. Tag result=success|failure. On success, mfa_used=true|false. On failure, reason carries LoginFailureReason.");

        _mfaChallenges = m.CreateCounter<long>(
            name: "auth.mfa.challenges.total",
            description: "MFA challenges issued. Tagged with provider.");
        
        _mfaVerifications = m.CreateCounter<long>(
            name: "auth.mfa.verifications.total",
            description: "MFA code verification outcomes. Tagged result=success|failure.");
        
        _refreshes = m.CreateCounter<long>(
            name: "auth.refreshes.total",
            description: "Refresh-token rotations that completed successfully. Reuse cascades are NOT counted here — see auth.refresh.reuse_detected.total.");
        
        _refreshReuseDetected = m.CreateCounter<long>(
            name: "auth.refresh.reuse_detected.total",
            description: "Refresh-token reuse cascades fired. Every increment is a security incident — alert on > 0 in any window.");
        
        _registrations = m.CreateCounter<long>(
            name: "auth.registrations.total",
            description: "Registration milestones. Tagged stage=registered|confirmed.");
        
        _lockouts = m.CreateCounter<long>(
            name: "auth.lockouts.total",
            description: "Account lockouts. Tagged trigger=failed_login|user|threshold_escalation.");
        
        _passwordChanges = m.CreateCounter<long>(
            name: "auth.password_changes.total",
            description: "Authenticated password changes.");
        
        _passwordResets = m.CreateCounter<long>(
            name: "auth.password_resets.total",
            description: "Password-reset flow milestones. Tagged stage=requested|completed.");
        
        _mfaEnabled = m.CreateCounter<long>(
            name: "auth.mfa.enabled.total",
            description: "MFA-enable events. Tagged with provider. Counts the act of enabling — NOT the running total of MFA users (see periodic gauge for that).");
        
        _tokensRevoked = m.CreateCounter<long>(
            name: "auth.tokens.revoked.total",
            description: "Access tokens revoked. Tagged with reason.");
        
        _revokedTokenReplays = m.CreateCounter<long>(
            name: "auth.revoked_token.replay.total",
            description: "Attempts to use a revoked access token. Tagged with severity.");
        
        _thresholdEscalations = m.CreateCounter<long>(
            name: "auth.threshold_escalation.fires.total",
            description: "Threshold-escalation worker fires. Tagged level=warned|locked. The 'locked' level is alert-worthy.");

        _clientCredentialsTokens = m.CreateCounter<long>(
            name: "auth.client_credentials.total",
            description: "OAuth client-credentials token requests. Tagged result=success|failure. On failure, reason carries the RFC 6749 error code (invalid_client / invalid_scope / unsupported_grant_type / invalid_request).");

        // Volatile.Read pairs with Volatile.Write in UpdateUserGauges.
        m.CreateObservableGauge(
            name: "auth.users.total",
            observeValue: () => Volatile.Read(ref _totalUsers),
            description: "Total registered users (refreshed periodically by UserGaugeRefreshService).");
        
        m.CreateObservableGauge(
            name: "auth.users.mfa_enabled.total",
            observeValue: () => Volatile.Read(ref _mfaEnabledUsers),
            description: "Users with MFA currently enabled.");
        
        m.CreateObservableGauge(
            name: "auth.users.locked.total",
            observeValue: () => Volatile.Read(ref _lockedUsers),
            description: "Users currently in an active lockout state (LockoutEnd > now).");
    }

    /// <summary>
    /// Snapshot update for the observable gauges. Called from <c>UserGaugeRefreshService</c>.
    /// </summary>
    public void UpdateUserGauges(long totalUsers, long mfaEnabledUsers, long lockedUsers)
    {
        Volatile.Write(ref _totalUsers, totalUsers);
        Volatile.Write(ref _mfaEnabledUsers, mfaEnabledUsers);
        Volatile.Write(ref _lockedUsers, lockedUsers);
    }

    // Emit methods — one per security event. Tag values must remain bounded.

    /// <summary>
    /// Records a successful login. <paramref name="mfaUsed"/> distinguishes MFA from password-only.
    /// </summary>
    public void LoginSucceeded(bool mfaUsed) =>
        _logins.Add(1,
            new KeyValuePair<string, object?>("result", "success"),
            new KeyValuePair<string, object?>("mfa_used", mfaUsed));

    /// <summary>
    /// Records a failed login attempt with the reason it was rejected.
    /// </summary>
    public void LoginFailed(LoginFailureReason reason) =>
        _logins.Add(1,
            new KeyValuePair<string, object?>("result", "failure"),
            new KeyValuePair<string, object?>("reason", reason.ToString()));

    /// <summary>
    /// Records that an MFA challenge was issued via the given provider.
    /// </summary>
    public void MfaChallengeIssued(MfaProviders provider) =>
        _mfaChallenges.Add(1, new KeyValuePair<string, object?>("provider", provider.ToString()));

    /// <summary>
    /// Records a successful MFA code verification.
    /// </summary>
    public void MfaVerified() =>
        _mfaVerifications.Add(1, new KeyValuePair<string, object?>("result", "success"));

    /// <summary>
    /// Records a failed MFA code verification.
    /// </summary>
    public void MfaFailed() =>
        _mfaVerifications.Add(1, new KeyValuePair<string, object?>("result", "failure"));

    /// <summary>
    /// Records a successful refresh-token rotation.
    /// </summary>
    public void RefreshTokenRotated() =>
        _refreshes.Add(1);

    /// <summary>
    /// Every increment is a security incident.
    /// </summary>
    public void RefreshTokenReuseDetected() =>
        _refreshReuseDetected.Add(1);

    /// <summary>
    /// Records a new user registering (account created, email not yet confirmed).
    /// </summary>
    public void RegistrationCompleted() =>
        _registrations.Add(1, new KeyValuePair<string, object?>("stage", "registered"));

    /// <summary>
    /// Records a user clicking the email-confirmation link.
    /// </summary>
    public void EmailConfirmed() =>
        _registrations.Add(1, new KeyValuePair<string, object?>("stage", "confirmed"));

    /// <summary>
    /// Triggers: <c>failed_login</c>, <c>user</c>, <c>threshold_escalation</c>.
    /// </summary>
    public void LockoutTriggered(string trigger) =>
        _lockouts.Add(1, new KeyValuePair<string, object?>("trigger", trigger));

    /// <summary>
    /// Records an authenticated password change.
    /// </summary>
    public void PasswordChanged() =>
        _passwordChanges.Add(1);

    /// <summary>
    /// Records a user kicking off the forgot-password flow.
    /// </summary>
    public void PasswordResetRequested() =>
        _passwordResets.Add(1, new KeyValuePair<string, object?>("stage", "requested"));

    /// <summary>
    /// Records a user completing a forgot-password reset.
    /// </summary>
    public void PasswordResetCompleted() =>
        _passwordResets.Add(1, new KeyValuePair<string, object?>("stage", "completed"));

    /// <summary>
    /// Records a user enabling MFA. Counts the act of enabling, not the running total.
    /// </summary>
    public void MfaEnabled(MfaProviders provider) =>
        _mfaEnabled.Add(1, new KeyValuePair<string, object?>("provider", provider.ToString()));

    /// <summary>
    /// Records an access token being added to the revoked list.
    /// </summary>
    public void TokenRevoked(string reason) =>
        _tokensRevoked.Add(1, new KeyValuePair<string, object?>("reason", reason));

    /// <summary>
    /// Records a replay attempt of a revoked access token. Severity is the <c>Severity</c> enum value (Low / Medium / High) stringified.
    /// </summary>
    public void RevokedTokenReplayAttempt(string severity) =>
        _revokedTokenReplays.Add(1, new KeyValuePair<string, object?>("severity", severity));

    /// <summary>
    /// Level: <c>warned</c> or <c>locked</c>. 'locked' also drives auth.lockouts.total via the caller.
    /// </summary>
    public void ThresholdEscalationFired(string level) =>
        _thresholdEscalations.Add(1, new KeyValuePair<string, object?>("level", level));

    public void ClientCredentialsTokenIssued() =>
        _clientCredentialsTokens.Add(1, new KeyValuePair<string, object?>("result", "success"));

    /// <summary>
    /// <paramref name="reason"/> is the RFC 6749 error code returned to the caller.
    /// </summary>
    public void ClientCredentialsTokenDenied(string reason) =>
        _clientCredentialsTokens.Add(1,
            new KeyValuePair<string, object?>("result", "failure"),
            new KeyValuePair<string, object?>("reason", reason));
}
