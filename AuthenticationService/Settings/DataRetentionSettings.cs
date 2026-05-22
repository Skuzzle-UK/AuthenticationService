using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Background cleanup sweep that prunes old audit/token rows.
/// </summary>
public class DataRetentionSettings
{
    /// <summary>
    /// How often the cleanup sweep runs. Bounded so a 0 / negative value can't crash
    /// <c>PeriodicTimer</c> at startup, and an absurdly large value can't silently
    /// disable cleanup.
    /// </summary>
    [Range(0.01, 168.0)]
    public double CleanupIntervalInHours { get; set; } = 12;

    /// <summary>
    /// How long <c>RevokedTokenAccessAttempt</c> audit rows are kept before they're deleted.
    /// </summary>
    [Range(1.0, 3650.0)]
    public double RevokedReplayTTLInDays { get; set; } = 90;

    /// <summary>
    /// Longer than replay audit — admin investigations look back further.
    /// </summary>
    [Range(1.0, 3650.0)]
    public double SecurityEventTTLInDays { get; set; } = 365;
}