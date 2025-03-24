using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Dtos;

public class MfaAuthenticationDto
{
    [Required]
    public string? Email { get; set; }

    [Required]
    public string? Provider { get; set; }

    [Required]
    public string? Token { get; set; }
}
