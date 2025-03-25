#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

public class AdminAccountSeedSettings
{
    [Required, EmailAddress]
    public string Email { get; set; }

    [Required]
    public string Password { get; set; }

    [Required, MaxLength(50)]
    public string FirstName { get; set; }

    [MaxLength(50)]
    public string? LastName { get; set; }

    [Phone]
    public string? PhoneNumber { get; set; }

    public bool PhoneNumberConfirmed { get; set; }

    [MaxLength(60)]
    public string? Country { get; set; }
}
