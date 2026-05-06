namespace AuthenticationService.Settings;

/// <summary>
/// Tuning knobs for <c>RevokedTokenReplayEscalationService</c> — the background worker
/// that watches for sustained replay of revoked tokens and locks the account when the
/// pattern looks like an attack.
///
/// <para>Defaults are aggressive on purpose: a well-behaved client retries at most once
/// with a stale token before refreshing, so anything beyond a couple of replays is either
/// a buggy client or active automation. Loosen the thresholds in deployments where
/// retry-on-old-token churn is expected (e.g. integration tests).</para>
/// </summary>
public class ThresholdEscalationSettings
{
    /// <summary>
    /// Master switch. Set to <c>false</c> to disable escalation entirely (useful during
    /// load testing, where you'd burn through these thresholds artificially).
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>How often the worker scans <c>RevokedTokenAccessAttempts</c>.</summary>
    public double SweepIntervalInMinutes { get; set; } = 1;

    /// <summary>The sliding-window size both thresholds are evaluated against.</summary>
    public double WindowInMinutes { get; set; } = 5;

    /// <summary>
    /// Replay count within the window that emits a Warning-level SIEM event
    /// (<see cref="Constants.SecurityEventIds.RevokedTokenReplayThresholdWarned"/>). No
    /// user-facing impact — informational only, helps spot buggy clients early.
    /// </summary>
    public int WarnThreshold { get; set; } = 2;

    /// <summary>
    /// Replay count within the window that locks the account, revokes every refresh-token
    /// family, and emails the user. Emits a Critical-level SIEM event
    /// (<see cref="Constants.SecurityEventIds.RevokedTokenReplayThresholdLocked"/>).
    /// </summary>
    public int LockThreshold { get; set; } = 5;
}
