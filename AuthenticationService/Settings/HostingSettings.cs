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
}
