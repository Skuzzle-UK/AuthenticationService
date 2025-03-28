using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class LockAccountDto
{
    [Required(ErrorMessage = "Email is required")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Username is required")]
    public string? UserName { get; set; }

    public string? FirstName { get; set; }

    public string? LastName { get; set; }

    public DateTime? DateOfBirth { get; set; }

    public string? Country { get; set; }
}
