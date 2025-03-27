using AuthenticationService.Shared.Enums;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

public class User : IdentityUser
{
    [MaxLength(50)]
    public string? FirstName { get; set; }

    [MaxLength(50)]
    public string? LastName { get; set; }

    [MaxLength(60)]
    public string? Country { get; set; }

    public bool WaitingForTwoFactorAuthentication { get; set; }

    public MfaProviders Preferred2FAProvider { get; set; }

    public string? RefreshToken { get; set; }

    public DateTime? RefreshTokenExpiresAt { get; set; }
}
