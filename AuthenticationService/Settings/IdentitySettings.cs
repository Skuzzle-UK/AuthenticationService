using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// ASP.NET Core Identity tuning knobs. Mirrors Identity's own nested shape; defaults align
/// with NIST 800-63B.
/// </summary>
public class IdentitySettings
{
    public PasswordSettings Password { get; set; } = new();
    public UserSettings User { get; set; } = new();
    public LockoutSettings Lockout { get; set; } = new();
}

public class PasswordSettings
{
    /// <summary>
    /// NIST 800-63B / OWASP guidance.
    /// </summary>
    [Range(1, 256)]
    public int RequiredLength { get; set; } = 12;

    /// <summary>
    /// Require at least one digit. Default true.
    /// </summary>
    public bool RequireDigit { get; set; } = true;

    /// <summary>
    /// Require at least one lowercase letter. Default true.
    /// </summary>
    public bool RequireLowercase { get; set; } = true;

    /// <summary>
    /// Require at least one uppercase letter. Default true.
    /// </summary>
    public bool RequireUppercase { get; set; } = true;

    /// <summary>
    /// Require at least one non-alphanumeric character. Default true.
    /// </summary>
    public bool RequireNonAlphanumeric { get; set; } = true;

    /// <summary>
    /// NIST 800-63B recommends NOT enforcing this — pushes users toward predictable patterns.
    /// Exposed for compliance frameworks that mandate it.
    /// </summary>
    [Range(1, 256)]
    public int RequiredUniqueChars { get; set; } = 1;
}

/// <summary>
/// User-creation settings.
/// </summary>
public class UserSettings
{
    /// <summary>
    /// Load-bearing for password-reset / account-recovery flows that look users up by email.
    /// </summary>
    public bool RequireUniqueEmail { get; set; } = true;

    /// <summary>
    /// Identity's default character set. Changing only affects new registrations.
    /// </summary>
    public string AllowedUserNameCharacters { get; set; } =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

    /// <summary>
    /// Usernames blocked at registration. Setting this in config REPLACES the default list
    /// — copy + extend rather than starting from nothing. <c>admin</c> is absent because
    /// the seeded admin already holds it; re-add if the seeder is removed.
    /// </summary>
    public List<string> ReservedUserNames { get; set; } = new()
    {
        // Admin / system role variants
        "administrator",
        "root",
        "system",
        "superuser",
        "sysadmin",

        // Platform identities (noreply, support mailboxes, etc.)
        "noreply",
        "no-reply",
        "support",
        "security",
        "help",
        "info",
        "contact",
        "abuse",
        "postmaster",
        "webmaster",

        // Fake-account markers / scanner artefacts
        "null",
        "undefined",
        "anonymous",
        "guest",
        "test",
        "user",

        // Service-account placeholders
        "service",
        "bot",
        "daemon",
    };
}

/// <summary>
/// Failed-login lockout settings.
/// </summary>
public class LockoutSettings
{
    /// <summary>
    /// Disabling means new accounts get unlimited password guesses with only the rate
    /// limiter as a backstop. Very high bar to turn off.
    /// </summary>
    public bool AllowedForNewUsers { get; set; } = true;

    /// <summary>
    /// Short by design — legitimate typos shouldn't lock users out for long. Active-attack
    /// scenarios are handled by the threshold-escalation worker (indefinite lock).
    /// </summary>
    [Range(0.1, 1440)]
    public double DefaultLockoutDurationInMinutes { get; set; } = 2;

    /// <summary>
    /// Failed login attempts before the account locks. Default 3. NIST 800-63B
    /// recommends "no more than 100" but that's a backstop — practical limits sit much
    /// lower. 3 is tight enough to matter against credential stuffing, generous enough
    /// for typical typos.
    /// </summary>
    [Range(1, 100)]
    public int MaxFailedAccessAttempts { get; set; } = 3;
}
