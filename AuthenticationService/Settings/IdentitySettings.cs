using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// Tuning knobs for ASP.NET Core Identity. Mirrors Identity's own nested options shape
/// (Password / User / Lockout) so the JSON config reads naturally. Defaults match the
/// values previously hardcoded in <c>HostExtensions.AddSecurity</c>; operators override
/// only what they want to tune.
///
/// <para>Most deployments shouldn't need to change these — defaults align with NIST 800-63B
/// (12-char password) and reasonable lockout protection. Common reasons to tune:</para>
/// <list type="bullet">
///   <item><description><b>Compliance frameworks</b> with specific length / complexity requirements (PCI-DSS, HIPAA, etc.)</description></item>
///   <item><description><b>Load tests / dev environments</b> needing looser caps on failed-attempt lockout to avoid breaking on retry</description></item>
///   <item><description><b>Internal-only deployments</b> where stronger or weaker password rules make sense</description></item>
/// </list>
/// </summary>
public class IdentitySettings
{
    public PasswordSettings Password { get; set; } = new();
    public UserSettings User { get; set; } = new();
    public LockoutSettings Lockout { get; set; } = new();
}

/// <summary>
/// Password-rule settings — what counts as a valid password at create / change time.
/// </summary>
public class PasswordSettings
{
    /// <summary>
    /// Minimum password length. Default 12 (NIST 800-63B / OWASP guidance).
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
    /// Minimum number of unique characters in a password. Default 1 (effectively no
    /// restriction). NIST 800-63B explicitly recommends *not* enforcing this rule —
    /// uniqueness rules push users toward predictable patterns. Exposed for compliance
    /// frameworks that mandate it; leave at default unless your auditor disagrees.
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
    /// Require unique email addresses across users. Default true. Don't turn this off
    /// without a very good reason — it's load-bearing for the password-reset / account-
    /// recovery flows that look users up by email.
    /// </summary>
    public bool RequireUniqueEmail { get; set; } = true;

    /// <summary>
    /// Characters allowed in usernames at registration. Identity's default permits letters,
    /// digits, and a small set of punctuation (<c>-._@+</c>). Tighten by removing characters
    /// (e.g. drop <c>+</c> if usernames are emails and you want to block gmail-alias style
    /// usernames). Note: changing this only affects new registrations — existing users
    /// keep their current usernames.
    /// </summary>
    public string AllowedUserNameCharacters { get; set; } =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

    /// <summary>
    /// Usernames blocked at registration to prevent display-confusion / social-engineering
    /// attacks. Operator-extensible — every corporate deployment likely has org-specific
    /// names worth blocking (e.g. <c>finance</c>, <c>infosec</c>, <c>payroll</c>) on top of
    /// the platform-generic defaults below. <b>Setting this in config replaces the default
    /// list entirely</b> — copy the defaults out and extend them rather than starting from
    /// nothing.
    ///
    /// <para><c>admin</c> is intentionally absent because the seeded admin account already
    /// holds that username; Identity's uniqueness constraint protects it. Re-add to this
    /// list if the seeder is ever removed.</para>
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
    /// Whether new users start with lockout enabled. Default true. The bar to disabling
    /// this is high — turning it off means brand-new accounts get unlimited password
    /// guesses with no rate-limit-style backstop besides the rate limiter itself.
    /// </summary>
    public bool AllowedForNewUsers { get; set; } = true;

    /// <summary>
    /// How long an account stays locked after exceeding <see cref="MaxFailedAccessAttempts"/>.
    /// Auto-clears at this duration. Default 2 minutes — short by design so a legitimate
    /// user who mistyped their password doesn't have to wait long. The threshold-escalation
    /// worker handles the "actively-attacked" case with indefinite locks.
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
