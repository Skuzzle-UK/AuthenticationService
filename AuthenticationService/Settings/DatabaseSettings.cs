#pragma warning disable CS8618 // Uninitialised non-nullable — properties bound by the Options pipeline at startup.
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Selects which EF Core provider <c>HostExtensions.AddDatabase</c> dispatches to.
/// </summary>
public class DatabaseSettings
{
    /// <summary>
    /// Canonical provider name. Must be one of <c>DatabaseProviders.Supported</c> —
    /// the validator fails startup if the value is unknown.
    /// </summary>
    [Required]
    public string Provider { get; set; } = "MySQL";
}
