namespace AuthenticationService.Settings;

public class RevokedTokenSettings
{
    public double CleanupIntervalInHours { get; set; } = 12;
    public double AccessRecordsTTLInDays { get; set; } = 90;
}