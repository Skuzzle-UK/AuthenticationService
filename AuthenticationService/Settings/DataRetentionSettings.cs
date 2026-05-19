namespace AuthenticationService.Settings;

/// <summary>
/// Controls the background cleanup sweep that prunes old audit and token rows so the
/// database doesn't grow forever.
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
    /// How long <c>SecurityEvents</c> audit rows are kept before they're deleted. Longer
    /// default than replay audit because admin investigations into "what did this user
    /// do six months ago?" are a real use case.
    /// </summary>
    public double SecurityEventTTLInDays { get; set; } = 365;
}