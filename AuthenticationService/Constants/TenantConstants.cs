using System.Text.RegularExpressions;

namespace AuthenticationService.Constants;

/// <summary>
/// Tenant-related constants — name-format rules, reserved names, and shared lookups.
/// See <c>docs/concepts/multi-tenancy-plan.md</c> Decision 6 for the validator design.
/// Tenant <c>Name</c> is the URL-friendly canonical identifier (Active Directory
/// convention); <c>DisplayName</c> is the human-facing label.
/// </summary>
public static partial class TenantConstants
{
    /// <summary>
    /// Name format: lowercase, alphanumeric + hyphens, starts and ends with alphanumeric,
    /// 3-50 characters total. Hyphens are allowed only in the middle.
    /// </summary>
    public const string NamePattern = @"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$";

    public const int NameMinLength = 3;
    public const int NameMaxLength = 50;

    /// <summary>
    /// Reserved tenant names — values that can't be used because they'd collide with
    /// URL path segments used by the auth service, or that would be confusing /
    /// misleading when shown to a user.
    /// </summary>
    public static readonly IReadOnlyList<string> ReservedNames =
    [
        "admin",
        "api",
        "www",
        "t",
        "tenant",
        "tenants",
        "oauth",
        "account",
        "login",
        "signup",
        "register",
        "logout",
        "forgot",
        "reset",
        "confirm",
        "mfa",
        ".well-known",
        "healthz",
        "livez",
        "readyz",
        "swagger",
        "superadmin",
        "system",
        "root",
        "auth",
    ];

    /// <summary>
    /// Pre-compiled regex for tenant-name format check. Source-generated for
    /// AOT-friendliness.
    /// </summary>
    [GeneratedRegex(NamePattern, RegexOptions.CultureInvariant)]
    public static partial Regex NameRegex();
}
