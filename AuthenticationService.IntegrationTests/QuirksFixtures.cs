namespace AuthenticationService.IntegrationTests.QuirksFixtures;

// Three provider-pinned fixtures + matching collection definitions for the
// multi-provider quirks suite. Each fixture forces a specific DB regardless of the
// INTEGRATION_DB_PROVIDER env var — the in-process suite exercises all three in a
// single `dotnet test` run, so it can't depend on the env-var selection that the
// bulk scenario suite uses.
//
// The CI matrix (.github/workflows/ci.yml) still drives the full scenario suite via
// INTEGRATION_DB_PROVIDER — these are additive, not replacements.

/// <summary>
/// AppHost pinned to MySQL via <c>--db-provider=MySQL</c>.
/// </summary>
public sealed class MySqlAppHostFixture : AppHostFixture
{
    public override string DbProvider => "MySQL";
    protected override string[] AppHostArgs =>
        ["--integration-test", "--rate-limiting-disabled", "--db-provider=MySQL"];
}

/// <summary>
/// AppHost pinned to SQL Server via <c>--db-provider=SqlServer</c>.
/// </summary>
public sealed class SqlServerAppHostFixture : AppHostFixture
{
    public override string DbProvider => "SqlServer";
    protected override string[] AppHostArgs =>
        ["--integration-test", "--rate-limiting-disabled", "--db-provider=SqlServer"];
}

/// <summary>
/// AppHost pinned to PostgreSQL via <c>--db-provider=PostgreSQL</c>.
/// </summary>
public sealed class PostgresAppHostFixture : AppHostFixture
{
    public override string DbProvider => "PostgreSQL";
    protected override string[] AppHostArgs =>
        ["--integration-test", "--rate-limiting-disabled", "--db-provider=PostgreSQL"];
}

// ─── Collection definitions ──────────────────────────────────────────────────────
// xUnit instantiates one fixture per collection. The quirks test classes use these
// to share their (slow-to-boot) AppHost graph across the handful of assertions in
// the class.

[CollectionDefinition(Name)]
public sealed class MySqlQuirksCollection : ICollectionFixture<MySqlAppHostFixture>
{
    public const string Name = "QuirksMySQL";
}

[CollectionDefinition(Name)]
public sealed class SqlServerQuirksCollection : ICollectionFixture<SqlServerAppHostFixture>
{
    public const string Name = "QuirksSqlServer";
}

[CollectionDefinition(Name)]
public sealed class PostgresQuirksCollection : ICollectionFixture<PostgresAppHostFixture>
{
    public const string Name = "QuirksPostgreSQL";
}
