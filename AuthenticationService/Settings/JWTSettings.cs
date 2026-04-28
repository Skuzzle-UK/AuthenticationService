#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

public class JWTSettings
{
    [Required]
    public string PrivateKeyPath { get; set; }

    public string? KeyId { get; set; }

    [Required]
    public string ValidIssuer { get; set; }

    [Required]
    public string ValidAudience { get; set; }

    [Required]
    public double ExpiryInMinutes { get; set; }

    [Required]
    public double RefreshTokenExpiryInDays { get; set; }
}
