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

    [Required(ErrorMessage = "Date of birth is required.")]
    public DateOnly? DateOfBirth { get; set; }

    [Required(ErrorMessage = "Email is required."), EmailAddress]
    public string? Email { get; set; }

    [Phone]
    public string? PhoneNumber { get; set; }

    [MaxLength(60)]
    public string? Country { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    public string? Password { get; set; }

    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string? ConfirmPassword { get; set; }

    public string? EmailConfirmationCallbackUri { get; set; }

    public MfaProviders? PreferredMfaProvider { get; set; }

    [MaxLength(150)]
    public string? MothersMaidenName { get; set; }

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
