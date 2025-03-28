namespace AuthenticationService.Settings;

public class RevokedTokenSettings
{
    public double CleanupIntervalInMinutes { get; set; } = 5;
    public double AccessRecordsTTLInDays { get; set; } = 5;
}