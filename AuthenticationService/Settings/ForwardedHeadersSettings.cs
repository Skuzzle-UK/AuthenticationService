namespace AuthenticationService.Settings;

/// <summary>
/// Configures which upstream proxies the service trusts when reading
/// <c>X-Forwarded-For</c> / <c>X-Forwarded-Proto</c> headers. Without populating these
/// lists, forwarded headers are ignored and <see cref="Microsoft.AspNetCore.Http.ConnectionInfo.RemoteIpAddress"/>
/// remains the proxy's IP rather than the real client — meaning audit IPs and the
/// rate-limiter's per-IP partition will both be wrong behind a load balancer.
///
/// Populate at least one of <see cref="KnownNetworks"/> or <see cref="KnownProxies"/>
/// in any environment that runs behind a proxy. Local-dev with no proxy can leave both
/// empty.
/// </summary>
public class ForwardedHeadersSettings
{
    /// <summary>
    /// CIDR blocks of trusted upstream proxies. Most production setups want this rather
    /// than <see cref="KnownProxies"/> — it covers the whole LB subnet without listing
    /// individual IPs. Format: <c>"10.0.0.0/8"</c>, <c>"192.168.1.0/24"</c>.
    /// </summary>
    public List<string> KnownNetworks { get; set; } = [];

    /// <summary>
    /// Specific IP addresses of trusted upstream proxies. Use when the LB IPs are stable
    /// and explicitly known. Format: <c>"10.0.0.5"</c>, <c>"203.0.113.10"</c>.
    /// </summary>
    public List<string> KnownProxies { get; set; } = [];
}
