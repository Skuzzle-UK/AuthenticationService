using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Service.AuthenticationGateway.Settings;

public class ServiceSettings
{
    [Required]
    [MinLength(64)]
    public required string SecurityKey { get; set; }
}
