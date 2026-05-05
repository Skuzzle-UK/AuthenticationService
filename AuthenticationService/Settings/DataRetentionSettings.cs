namespace AuthenticationService.Settings;

public class DataRetentionSettings
{
    public double CleanupIntervalInHours { get; set; } = 12;
    public double AccessRecordsTTLInDays { get; set; } = 90;
}
