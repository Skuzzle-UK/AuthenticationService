using Microsoft.EntityFrameworkCore.Infrastructure;

namespace AuthenticationService.Constants;

/// <summary>
/// Canonical names for supported EF Core database providers. Used by
/// <c>DatabaseSettings.Provider</c> + the dispatch in <c>HostExtensions.AddDatabase</c>.
/// All three providers in this class are now wired — multi-provider plan complete.
/// </summary>
public static class DatabaseProviders
{
    public const string MySql = "MySQL";
    public const string SqlServer = "SqlServer";
    public const string PostgreSQL = "PostgreSQL";

    /// <summary>
    /// Providers the host will actually start under.
    /// </summary>
    public static readonly IReadOnlyList<string> Supported = [MySql, SqlServer, PostgreSQL];
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
