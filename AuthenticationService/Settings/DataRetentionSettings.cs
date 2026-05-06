namespace AuthenticationService.Settings;

/// <summary>
/// Controls the background cleanup sweep that prunes old audit and token rows so the
/// database doesn't grow forever.
/// </summary>
public class DataRetentionSettings
{
    /// <summary>How often the cleanup sweep runs.</summary>
    public double CleanupIntervalInHours { get; set; } = 12;

    /// <summary>How long <c>AccessRecord</c> audit rows are kept before they're deleted.</summary>
    public double AccessRecordsTTLInDays { get; set; } = 90;
}
