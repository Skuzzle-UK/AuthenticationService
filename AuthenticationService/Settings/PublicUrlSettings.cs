#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Where this service is publicly reachable. Used by background workers (e.g. the
/// threshold-escalation worker) to build links in emails — they have no HttpContext to
/// derive a base URL from. Set to the canonical public URL in production
/// (<c>https://auth.example.com</c>); the dev default in <c>appsettings.Development.json</c>
/// is <c>https://localhost:53217</c> so <c>dotnet run</c> Just Works.
/// </summary>
public class PublicUrlSettings
{
    /// <summary>
    /// Scheme + host (+ optional port) of the auth service from a user's browser. No
    /// trailing slash. Background workers append <c>RouteConstants.ResetPassword</c> etc.
    /// to this when constructing email links.
    /// </summary>
    [Required]
    public string BaseUrl { get; set; }
}
