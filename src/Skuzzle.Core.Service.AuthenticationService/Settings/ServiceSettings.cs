using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Service.AuthenticationService.Settings;

public class ServiceSettings
{
    [Required]
    [MinLength(64)]
    public required string SecurityKey { get; set; }
}
