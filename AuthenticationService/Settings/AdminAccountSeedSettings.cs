#pragma warning disable CS8618 // Uninitialised non-nullable — properties bound by the Options pipeline at startup.
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

    /// <summary>
    /// Break-glass recovery flag. When <c>true</c>, the seeder resets the existing admin
    /// account on startup (clears lockout, resets password from <c>Password</c>, disables
    /// MFA, revokes sessions). Off by default — set, restart, then unset to avoid every
    /// subsequent restart re-resetting the admin. See docs/operations/admin-recovery.md.
    /// </summary>
    public bool ResetOnStartup { get; set; }
}
