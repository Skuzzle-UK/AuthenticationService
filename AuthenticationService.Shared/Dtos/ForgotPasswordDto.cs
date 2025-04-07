using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class ForgotPasswordDto
{
    [Required(ErrorMessage = "Email is required.")]
    public string? Email { get; set; }

    public string? ResetPasswordUri { get; set; }
}