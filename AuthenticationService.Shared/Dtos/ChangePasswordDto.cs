using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class ChangePasswordDto
{
    [Required(ErrorMessage = "Email is required.")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Old password is required.")]
    public string? OldPassword { get; set; }

    [Required(ErrorMessage = "New password is required.")]
    public string? NewPassword { get; set; }

    [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
    public string? ConfirmPassword { get; set; }

    public string? LockAccountUri { get; set; }
}
