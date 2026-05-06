namespace AuthenticationService.Settings;

/// <summary>
/// Cross-Origin Resource Sharing config for browser-based clients. Origins must be
/// explicitly allow-listed; an empty list blocks all cross-origin traffic. Wildcards
/// are deliberately not supported by the underlying policy — that's a security choice,
/// not a configuration limitation.
/// </summary>
public class CorsSettings
{
    /// <summary>
    /// Origins (scheme + host + port) allowed to call this API from a browser.
    /// Format: <c>"https://app.example.com"</c> — no trailing slash, no path.
    /// Empty list = no cross-origin access.
    /// </summary>
    public List<string> AllowedOrigins { get; set; } = [];
}
