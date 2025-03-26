using AuthenticationService.Shared.Enums;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class MfaAuthenticationDto
{
    [Required(ErrorMessage = "Email is required.")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "MfaProvider is required.")]
    public MfaProviders? MfaProvider { get; set; }

    [Required(ErrorMessage = "Token is required.")]
    public string? Token { get; set; }
}
