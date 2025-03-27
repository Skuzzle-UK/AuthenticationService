using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class RefreshTokenDto
{
    [Required(ErrorMessage = "RefreshToken is required.")]
    public string? RefreshToken { get; set; }
}
