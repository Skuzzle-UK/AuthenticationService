using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class ForgotPasswordDto
{
    [Required(ErrorMessage = "Email is required.")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Callback URI is required so that we know where the email link should take you to.")]
    public string? CallbackUri { get; set; }
}