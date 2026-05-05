namespace AuthenticationService.Settings;

/// <summary>
/// Configuration for ASP.NET Core's data-protection key ring. Drives where keys are
/// persisted (Redis) and, optionally, how they're protected at rest (X.509 certificate).
/// </summary>
public class DataProtectionSettings
{
    /// <summary>
    /// Redis hash key under which the data-protection keys are stored. Should be unique
    /// per application — multiple ASP.NET apps sharing the same Redis must not share this key.
    /// </summary>
    public string RedisKey { get; set; } = "AuthenticationService:DataProtectionKeys";

    /// <summary>
    /// ASP.NET Core data-protection application name. Replicas of this service must share
    /// the same value; different applications sharing a Redis must use different values.
    /// Do not change once deployed — changing invalidates all outstanding Identity tokens.
    /// </summary>
    public string ApplicationName { get; set; } = "AuthenticationService";

    /// <summary>
    /// Optional certificate that wraps the data-protection keys at rest. When configured,
    /// keys persisted to Redis are encrypted with the cert and useless without it. Strongly
    /// recommended for production. Can be added after initial deploy without code changes —
    /// just populate this section in config.
    /// </summary>
    public DataProtectionCertificateSettings? Certificate { get; set; }
}