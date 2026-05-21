using AuthenticationService.Entities;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace AuthenticationService.Tests.Helpers;

/// <summary>
/// Test-only subclass of <see cref="DatabaseContext"/> that papers over SQLite quirks.
/// Currently maps <c>User.LockoutEnd</c> through a DateTimeOffset → UtcTicks converter
/// so SQLite can translate <c>Where(u =&gt; u.LockoutEnd &gt; now)</c> (otherwise EF throws
/// at translation time on the ambiguous lexicographic ordering).
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
