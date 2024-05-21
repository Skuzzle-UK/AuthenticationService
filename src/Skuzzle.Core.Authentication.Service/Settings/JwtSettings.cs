using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Authentication.Service.Settings;

public class JwtSettings
{
    [Required]
    [MinLength(64)]
    public required string Key { get; set; }

    [Required]
    public required string Issuer { get; set; }

    [Required]
    public required string Audience { get; set; }

    [Required]
    public required int TtlSeconds { get; set; }

    [Required]
    public required int RefreshTtlSeconds { get; set; }
}
