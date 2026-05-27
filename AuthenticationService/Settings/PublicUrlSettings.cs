#pragma warning disable CS8618 // Uninitialised non-nullable — properties bound by the Options pipeline at startup.
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Publicly-reachable URL of the auth service. Used by background workers (no HttpContext)
/// to build email links.
/// </summary>
public class PublicUrlSettings
{
    /// <summary>
    /// Scheme + host (+ optional port). No trailing slash.
    /// </summary>
    [Required]
    public string BaseUrl { get; set; }
}
