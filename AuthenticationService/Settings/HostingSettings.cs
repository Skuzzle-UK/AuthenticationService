using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Per-deployment hosting flags. Lets the same image run as an API replica (workers off,
/// HTTP traffic on) or a worker replica (workers on, no HTTP traffic routed). Defaults
/// keep single-deployment setups working unchanged.
/// </summary>
public class HostingSettings
{
    /// <summary>
    /// Set to false on API replicas in a multi-replica deployment.
    /// </summary>
    public bool BackgroundWorkersEnabled { get; set; } = true;

    /// <summary>
    /// Kestrel's own 30 MB default is a needless DoS surface for an auth API where every
    /// body is small JSON. Raise only when an endpoint legitimately needs larger payloads.
    /// </summary>
    [Range(1, 30720)]
    public int MaxRequestBodySizeInKilobytes { get; set; } = 1024;

    /// <summary>
    /// Production should always leave this enabled. Integration tests turn it off so a
    /// sequence of credential calls doesn't trip the global cap.
    /// </summary>
    public bool RateLimitingEnabled { get; set; } = true;

    /// <summary>
    /// Production should always leave this enabled. Integration tests turn it off — the
    /// dev cert dance on Linux CI is fragile and they only hit localhost.
    /// </summary>
    public bool HttpsRedirectionEnabled { get; set; } = true;
}

