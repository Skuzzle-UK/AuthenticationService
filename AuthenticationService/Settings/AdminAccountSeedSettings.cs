#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Default admin account seeded on first startup. <c>Password</c> must come from env vars
/// / user-secrets / secret store outside Development — never check it into appsettings.
/// </summary>
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
