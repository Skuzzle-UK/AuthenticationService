using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Data-protection key ring config (Redis persistence + optional at-rest cert).
/// </summary>
public class DataProtectionSettings
{
    /// <summary>
    /// Must be unique per application sharing the Redis instance.
    /// </summary>
    [Required]
    public string RedisKey { get; set; } = "AuthenticationService:DataProtectionKeys";

    /// <summary>
    /// Replicas must share the same value. Don't change once deployed — invalidates all
    /// outstanding Identity tokens.
    /// Required: a blank value would silently invalidate every issued token next deploy.
    /// </summary>
    [Required]
    public string ApplicationName { get; set; } = "AuthenticationService";

    /// <summary>
    /// Optional at-rest encryption certificate. Strongly recommended in production; can
    /// be added post-deploy without code changes.
    /// </summary>
    public DataProtectionCertificateSettings? Certificate { get; set; }
}