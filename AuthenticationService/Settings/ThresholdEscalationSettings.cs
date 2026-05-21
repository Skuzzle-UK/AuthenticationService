namespace AuthenticationService.Settings;

/// <summary>
/// Tuning for <c>RevokedTokenReplayEscalationService</c>. Defaults are aggressive — a
/// well-behaved client retries at most once on a stale token. Loosen for environments with
/// expected stale-token churn (integration tests).
/// </summary>
public class ThresholdEscalationSettings
{
    /// <summary>
    /// Master switch — useful for load testing where thresholds would burn through.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How often the worker scans <c>RevokedTokenAccessAttempts</c>.
    /// </summary>
    public double SweepIntervalInMinutes { get; set; } = 1;

    /// <summary>
    /// Sliding window both thresholds are evaluated against.
    /// </summary>
    public double WindowInMinutes { get; set; } = 5;

    /// <summary>
    /// Replays in the window that emit a Warning SIEM event. No user-facing impact.
    /// </summary>
    public int WarnThreshold { get; set; } = 2;

    /// <summary>
    /// Replays in the window that lock the account, revoke every refresh-token family, and
    /// email the user. Emits a Critical SIEM event.
    /// </summary>
    public int LockThreshold { get; set; } = 5;
}
