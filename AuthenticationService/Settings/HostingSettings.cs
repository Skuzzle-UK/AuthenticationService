using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Per-deployment hosting flags. Lets the same Docker image run as either an API replica
/// (handles HTTP traffic, no background workers) or a worker replica (runs the cleanup
/// sweep and threshold-escalation worker, no API traffic routed to it). Default is
/// <c>BackgroundWorkersEnabled = true</c> for backwards compatibility — single-deployment
/// setups continue to work unchanged.
///
/// <para>For multi-replica K8s deployments the recommended pattern is two Deployments
/// from the same image:</para>
/// <list type="bullet">
///   <item><description><b>API Deployment</b> (replicas: 3+) with <c>HostingSettings__BackgroundWorkersEnabled=false</c>. Receives HTTP traffic.</description></item>
///   <item><description><b>Worker Deployment</b> (replicas: 1) with default settings. Runs the workers; not in the API's K8s Service so no traffic is routed.</description></item>
/// </list>
/// </summary>
public class HostingSettings
{
    /// <summary>
    /// True (default) → register the background hosted services on this replica
    /// (<c>DataRetentionCleanupService</c>, <c>RevokedTokenReplayEscalationService</c>).
    /// Set to <c>false</c> on API replicas of a multi-replica deployment so only the
    /// dedicated worker replica runs them.
    /// </summary>
    public bool BackgroundWorkersEnabled { get; set; } = true;

    /// <summary>
    /// Cap on inbound request body size, in kilobytes. Default 1024 (1 MB). Kestrel's own
    /// default of 30 MB is far larger than anything an auth endpoint legitimately accepts
    /// — login / registration / refresh bodies are all small JSON — so we cap it tight to
    /// shrink the DoS surface. Raise this if a future endpoint legitimately accepts larger
    /// payloads (e.g. avatar upload). Hard-capped at 30 MB (Kestrel's own default) — at
    /// that point the config-time cap is no longer doing anything useful.
    /// </summary>
    [Range(1, 30720)]
    public int MaxRequestBodySizeInKilobytes { get; set; } = 1024;

    /// <summary>
    /// True (default) → wire up the rate limiter middleware with the policies defined in
    /// <c>RateLimiterOptionsConfigurator</c>. Set to <c>false</c> in integration-test
    /// environments so a sequence of tests calling credential endpoints doesn't trip the
    /// global 4/10s cap. <b>Production should always leave this enabled</b> — disabling
    /// removes the credential-stuffing / DDoS defence that the unit tests cover but the
    /// real wire enforces.
    /// </summary>
    public bool RateLimitingEnabled { get; set; } = true;
}

