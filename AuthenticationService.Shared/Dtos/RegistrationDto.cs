using AuthenticationService.Shared.Enums;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class RegistrationDto
{
    [Required(ErrorMessage = "UserName is required."), MaxLength(50)]
    public string? UserName { get; set; }
    
    [MaxLength(50)]
    public string? FirstName { get; set; }

    [MaxLength(50)]
    public string? LastName { get; set; }

    [Required(ErrorMessage = "Email is required.")]
    public string? Email { get; set; }

    [Phone]
    public string? PhoneNumber { get; set; }

    [MaxLength(60)]
    public string? Country { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    public string? Password { get; set; }

    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string? ConfirmPassword { get; set; }

    public string? CallbackUri { get; set; }

    public MfaProviders? Preferred2FAProvider { get; set; }
}
