#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

public class JWTSettings
{
    [Required]
    public string SecurityKey { get; set; }

    [Required]
    public string ValidIssuer { get; set; }

    [Required]
    public string ValidAudience { get; set; }

    [Required]
    public int ExpiryInMinutes { get; set; }
}
