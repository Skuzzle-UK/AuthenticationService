#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Details for the default admin account that gets seeded into the database on first
/// startup. Most fields live in <c>appsettings.json</c>; <c>Password</c> is dev-only and
/// must be supplied via env var / user-secrets / secret store outside Development.
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
