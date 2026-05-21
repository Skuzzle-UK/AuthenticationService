namespace AuthenticationService.Settings;

/// <summary>
/// Trusted upstream proxies for <c>X-Forwarded-*</c> headers. Populate at least one list
/// in any environment behind a proxy — otherwise RemoteIpAddress is the proxy IP and audit
/// / rate-limiting are wrong.
/// </summary>
public class ForwardedHeadersSettings
{
    /// <summary>
    /// CIDR blocks (e.g. <c>"10.0.0.0/8"</c>). Usually preferred over <see cref="KnownProxies"/>.
    /// </summary>
    public List<string> KnownNetworks { get; set; } = [];

    /// <summary>
    /// Specific IPs (e.g. <c>"10.0.0.5"</c>).
    /// </summary>
    public List<string> KnownProxies { get; set; } = [];
}
