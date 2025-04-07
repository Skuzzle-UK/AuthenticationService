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

    public DateOnly? DateOfBirth { get; set; }

    [MaxLength(60)]
    public string? Country { get; set; }

    public bool WaitingForTwoFactorAuthentication { get; set; }

    public MfaProviders Preferred2FAProvider { get; set; }

    public string? RefreshToken { get; set; }

    public DateTime? RefreshTokenExpiresAt { get; set; }

    [MaxLength(150)]
    public string? MotherMaidenName { get; set; }

    [MaxLength(256)]
    public string? AddressLine1 { get; set; }

    [MaxLength(256)]
    public string? AddressLine2 { get; set; }

    [MaxLength(256)]
    public string? AddressLine3 { get; set; }

    [MaxLength(20)]
    public string? Postcode { get; set; }

    [MaxLength(60)]
    public string? City { get; set; }
}
