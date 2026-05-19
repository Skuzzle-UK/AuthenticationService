using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Tuning for the <c>POST /oauth/token</c> client-credentials endpoint. Defaults reflect
/// the design decisions in <c>docs/service-to-service-auth-plan.md</c>:
/// <list type="bullet">
///   <item><description>12h token lifetime — longer than user tokens (5 min) because services have no refresh-token machinery; they just re-request when their token expires. 12h sits in the "batch / data-loader / scheduled job" sweet spot.</description></item>
///   <item><description>HTTPS required by default. Disable only for local dev / integration tests over the HTTP transport.</description></item>
/// </list>
/// </summary>
public class ClientCredentialsSettings
{
    /// <summary>
    /// Lifetime of issued service-identity JWTs. Service tokens can't be refreshed —
    /// when this expires the calling service re-authenticates via <c>/oauth/token</c>.
    /// </summary>
    [Range(0.0, 168.0, ErrorMessage = "ClientCredentialsSettings:TokenLifetimeInHours must be between 0 (immediate) and 168 (1 week).")]
    public double TokenLifetimeInHours { get; set; } = 12;

    /// <summary>
    /// When true, <c>/oauth/token</c> rejects HTTP requests with <c>invalid_request</c>.
    /// Default true; integration-test fixture flips this off when running over the http
    /// endpoint (mirrors the existing <c>HostingSettings:HttpsRedirectionEnabled</c>
    /// pattern).
    /// </summary>
    public bool RequireHttps { get; set; } = true;
}
