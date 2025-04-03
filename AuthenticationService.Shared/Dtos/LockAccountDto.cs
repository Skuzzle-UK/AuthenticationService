using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class LockAccountDto
{
    [Required(ErrorMessage = "Email is required.")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Token is required.")]
    public string? Token { get; set; }
}
