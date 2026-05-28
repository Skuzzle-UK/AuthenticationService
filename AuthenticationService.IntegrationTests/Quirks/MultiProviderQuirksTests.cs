using AuthenticationService.IntegrationTests.QuirksFixtures;
using AwesomeAssertions;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests.Quirks;

// In-process multi-provider quirks suite. The CI matrix already runs the full 15
// scenarios against each provider in parallel; these tests are additive — they boot
// MySQL + SqlServer + PostgreSQL containers in one test run so divergence at the
// EF / SQL layer surfaces on a local `dotnet test` invocation without waiting for CI.
//
// Tagged with `MultiProviderQuirks` so the default test run can skip them and the
// usual `dotnet test` flow (single provider via INTEGRATION_DB_PROVIDER) stays fast.
// To opt in:
//
//   dotnet test --filter "Category=MultiProviderQuirks"
//
// One container set per provider boots serially (xUnit collection fixtures), so this
// adds roughly 90s of cold-pull walltime to a clean run; cached image pulls bring
// that down to ~30s. Worth the cost when touching the EF model or the
// `IsMySql()`-gated runtime workarounds.

/// <summary>
/// Shared test methods. Concrete subclasses pin a specific fixture via the relevant
/// quirks collection. Tests assert the surfaces that *actually* diverge between
/// providers — DateTimeOffset / DateOnly column round-trips — and rely on the rest of
/// the integration suite (covered by the CI matrix) for end-to-end flow coverage.
/// </summary>
public abstract class MultiProviderQuirksTestsBase(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    [Trait("Category", "MultiProviderQuirks")]
    public async Task UserRegistration_RoundTripsDateOnlyAndDateTimeOffset()
    {
        // arrange
        // DateOnly: MySQL goes through the DateOnly?→DateTime? value converter
        // (DatabaseContext.OnModelCreating, IsMySql branch); SqlServer + PostgreSQL map
        // DateOnly natively. The literal 1990-01-01 should come back identical on all three.
        var dob = new DateOnly(1990, 1, 1);
        var beforeRegister = DateTimeOffset.UtcNow;

        // act
        // RegisterAndConfirmUserAsync seeds with DateOfBirth=1990-01-01 internally.
        var user = await RegisterAndConfirmUserAsync();
        var afterRegister = DateTimeOffset.UtcNow;

        // assert — read the persisted row directly and check both fields round-trip.
        await using var db = await CreateDbContextAsync();
        var persisted = await db.Users
            .AsNoTracking()
            .SingleAsync(u => u.Email == user.Email);

        persisted.DateOfBirth.Should().Be(dob,
            because: $"DateOnly should round-trip identically on {Fixture.DbProvider} " +
                     "(MySQL via value converter, others natively).");

        // CreatedAt: DateTimeOffset round-trip. We allow a small window because the
        // server stamps its own value at User construction (User.cs's initialiser).
        // MySQL stores via datetime(6) with the offset dropped (always reads back as
        // +00:00); SqlServer preserves the original offset via native datetimeoffset;
        // PostgreSQL normalises to UTC (reads back as +00:00). The service uses
        // DateTimeOffset.UtcNow throughout so offset=zero is correct on every provider.
        persisted.CreatedAt.Should().BeOnOrAfter(beforeRegister.AddSeconds(-1),
            because: "CreatedAt should be stamped close to wall-clock at registration.");
        persisted.CreatedAt.Should().BeOnOrBefore(afterRegister.AddSeconds(1),
            because: "CreatedAt should not be far in the future.");
        persisted.CreatedAt.Offset.Should().Be(TimeSpan.Zero,
            because: $"server stamps with DateTimeOffset.UtcNow; {Fixture.DbProvider} " +
                     "should read it back with offset=00:00.");
    }

    [Fact]
    [Trait("Category", "MultiProviderQuirks")]
    public async Task Migrations_AppliedCleanly_OnEveryProvider()
    {
        // The fixture's StartAsync triggers auth's startup, which runs
        // app.RunMigrations() → Database.Migrate() against the live DB. By the time we
        // get here, every migration in the provider's assembly should be applied.
        //
        // Catches: a migration that fails to apply on a specific provider — Phase 3.4's
        // ExitCode=1 makes startup crashes visible at the process level, this asserts
        // it positively at the DB level by reading the __EFMigrationsHistory table.
        //
        // We deliberately don't assert HasPendingModelChanges() — that API can return
        // true even when `dotnet ef migrations add` produces an empty migration (model
        // differ flags annotation-level differences that don't translate to schema
        // changes; the EF tools 10.0.2 vs runtime 10.0.8 version mismatch we run with
        // is a known producer of these false positives). When real model drift lands,
        // it shows up as a non-empty migration body or as a query/scenario failure in
        // the CI matrix — both of which are higher-signal than the model-differ result.

        // arrange
        await using var db = await CreateDbContextAsync();

        // act
        var applied = await db.Database.GetAppliedMigrationsAsync();
        var pending = await db.Database.GetPendingMigrationsAsync();

        // assert
        applied.Should().NotBeEmpty(
            because: $"every provider has migrations to apply on a fresh DB — empty " +
                     $"AppliedMigrations on {Fixture.DbProvider} means auth booted but " +
                     "Database.Migrate() didn't run, or the migrations assembly is empty.");

        pending.Should().BeEmpty(
            because: $"all migrations in the {Fixture.DbProvider} assembly should have " +
                     "been applied during auth startup; pending entries mean a migration " +
                     "exists in the assembly but didn't apply (rare — usually a partial-fail).");
    }
}

// Class-level Trait on each concrete subclass so the `Category!=MultiProviderQuirks`
// filter applied by CI and by default-local `dotnet test` keeps these out. xUnit treats
// [Trait] on a derived class as applying to its inherited methods, which is what we want.

[Trait("Category", "MultiProviderQuirks")]
[Collection(MySqlQuirksCollection.Name)]
public sealed class MySqlMultiProviderQuirksTests(MySqlAppHostFixture fixture)
    : MultiProviderQuirksTestsBase(fixture);

[Trait("Category", "MultiProviderQuirks")]
[Collection(SqlServerQuirksCollection.Name)]
public sealed class SqlServerMultiProviderQuirksTests(SqlServerAppHostFixture fixture)
    : MultiProviderQuirksTestsBase(fixture);

[Trait("Category", "MultiProviderQuirks")]
[Collection(PostgresQuirksCollection.Name)]
public sealed class PostgresMultiProviderQuirksTests(PostgresAppHostFixture fixture)
    : MultiProviderQuirksTestsBase(fixture);
