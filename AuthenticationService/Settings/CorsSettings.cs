namespace AuthenticationService.Settings;

/// <summary>
/// CORS config. Explicit allow-list only — wildcards are deliberately unsupported.
/// Empty list blocks all cross-origin traffic.
/// </summary>
public class CorsSettings
{
    /// <summary>
    /// Origins as scheme+host+port (e.g. <c>"https://app.example.com"</c>) — no trailing slash.
    /// </summary>
    public List<string> AllowedOrigins { get; set; } = [];
}
