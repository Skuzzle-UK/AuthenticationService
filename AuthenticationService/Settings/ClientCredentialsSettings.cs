using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Tuning for the <c>POST /oauth/token</c> client-credentials endpoint. 12h default token
/// lifetime — longer than user tokens because services have no refresh machinery and just
/// re-request on expiry.
/// </summary>
public class ClientCredentialsSettings
{
    /// <summary>
    /// Service tokens can't be refreshed — caller re-authenticates on expiry.
    /// </summary>
    [Range(0.0, 168.0, ErrorMessage = "ClientCredentialsSettings:TokenLifetimeInHours must be between 0 (immediate) and 168 (1 week).")]
    public double TokenLifetimeInHours { get; set; } = 12;

    /// <summary>
    /// Integration tests flip this off when running over HTTP. Mirrors
    /// HostingSettings:HttpsRedirectionEnabled.
    /// </summary>
    public bool RequireHttps { get; set; } = true;
}
