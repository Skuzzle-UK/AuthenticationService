using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Dtos;

public class UserAuthenticationDto
{
    [Required(ErrorMessage = "Email is required.")]
    public string? Email { get; set; }
    [Required(ErrorMessage = "Password is required.")]
    public string? Password { get; set; }
}
