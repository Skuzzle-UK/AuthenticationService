using Microsoft.EntityFrameworkCore.Infrastructure;

namespace AuthenticationService.Constants;

/// <summary>
/// Canonical names for supported EF Core database providers. Used by
/// <c>DatabaseSettings.Provider</c> + the dispatch in <c>HostExtensions.AddDatabase</c>.
/// <c>SqlServer</c> and <c>PostgreSQL</c> are reserved for Phases 2 and 3 of the
/// multi-provider plan (see TODO.md) — referenced from the validator's allowed-set
/// even though the dispatch case hasn't been wired yet would be a footgun, so they're
/// not in <see cref="Supported"/> until each phase ships.
/// </summary>
public static class DatabaseProviders
{
    public const string MySql = "MySQL";
    public const string SqlServer = "SqlServer";
    public const string PostgreSQL = "PostgreSQL";

    /// <summary>
    /// Providers the host will actually start under. Grows as multi-provider phases land.
    /// </summary>
    public static readonly IReadOnlyList<string> Supported = [MySql];
}

/// <summary>
/// Helpers for branching workarounds on the active provider at runtime. We check by
/// substring on <c>ProviderName</c> so both Oracle's <c>MySql.EntityFrameworkCore</c>
/// and Pomelo's <c>Pomelo.EntityFrameworkCore.MySql</c> match — the eventual Pomelo
/// swap then doesn't have to revisit every workaround site.
/// </summary>
public static class DatabaseProviderExtensions
{
    public static bool IsMySql(this DatabaseFacade db) =>
        db.ProviderName?.Contains("MySql", StringComparison.OrdinalIgnoreCase) == true;
}
