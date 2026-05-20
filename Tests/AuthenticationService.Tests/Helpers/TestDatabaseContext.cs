using AuthenticationService.Entities;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace AuthenticationService.Tests.Helpers;

/// <summary>
/// Test-only subclass of <see cref="DatabaseContext"/> that papers over SQLite's
/// provider-level quirks for unit tests. Production <see cref="DatabaseContext"/> stays
/// provider-agnostic — anything that's a workaround for "we picked SQLite for fast
/// in-memory unit tests, but our production database is MySQL" lives here.
///
/// <para>Currently the only quirk it handles:</para>
/// <list type="bullet">
///   <item><description><b><c>User.LockoutEnd</c> binary comparison.</b> ASP.NET Core Identity
///   maps the column as <see cref="DateTimeOffset"/>?, and the SQLite EF provider refuses to
///   translate <c>Where(u =&gt; u.LockoutEnd &gt; now)</c> (ambiguous lexicographic ordering
///   across timezone offsets — the comparison throws
///   <c>InvalidOperationException</c> at query-translation time). The
///   <see cref="ValueConverter{TModel,TProvider}"/> below converts the column to
///   <c>long?</c> (<c>UtcTicks</c>) on read/write so the comparison becomes long-vs-long,
///   which SQLite handles trivially. <c>UtcTicks</c> is instant-preserving, so round-trip
///   semantics are exact.</description></item>
/// </list>
///
/// <para>Test fixtures that need the converter should construct via
/// <c>new DbContextOptionsBuilder&lt;TestDatabaseContext&gt;().UseSqlite(connection).Options</c>
/// and instantiate <see cref="TestDatabaseContext"/> directly. Services typed against
/// <see cref="DatabaseContext"/> accept the subclass via inheritance.</para>
/// </summary>
internal sealed class TestDatabaseContext : DatabaseContext
{
    public TestDatabaseContext(DbContextOptions options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        var dateTimeOffsetToUtcTicks = new ValueConverter<DateTimeOffset?, long?>(
            v => v.HasValue ? v.Value.UtcTicks : null,
            v => v.HasValue ? new DateTimeOffset(v.Value, TimeSpan.Zero) : null);

        builder.Entity<User>()
            .Property(u => u.LockoutEnd)
            .HasConversion(dateTimeOffsetToUtcTicks);
    }
}
