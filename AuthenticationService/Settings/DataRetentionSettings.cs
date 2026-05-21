namespace AuthenticationService.Settings;

/// <summary>
/// Background cleanup sweep that prunes old audit/token rows.
/// </summary>
public class DataRetentionSettings
{
    /// <summary>
    /// How often the cleanup sweep runs.
    /// </summary>
    public double CleanupIntervalInHours { get; set; } = 12;

    /// <summary>
    /// How long <c>RevokedTokenAccessAttempt</c> audit rows are kept before they're deleted.
    /// </summary>
    public double RevokedReplayTTLInDays { get; set; } = 90;

    /// <summary>
    /// Longer than replay audit — admin investigations look back further.
    /// </summary>
    public double SecurityEventTTLInDays { get; set; } = 365;
}