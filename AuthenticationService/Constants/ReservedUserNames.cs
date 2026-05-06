namespace AuthenticationService.Constants;

/// <summary>
/// Usernames blocked at registration to prevent display-confusion / social-engineering
/// attacks. Comparison is case-insensitive and ignores leading/trailing whitespace.
/// </summary>
public static class ReservedUserNames
{
    public static readonly HashSet<string> Names = new(StringComparer.OrdinalIgnoreCase)
{
    // Admin / system role variants
    // admin is intentionally left out as admin user is seeded
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

    public static bool IsReserved(string? userName) =>
        !string.IsNullOrWhiteSpace(userName) && Names.Contains(userName.Trim());
}