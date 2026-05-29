using AuthenticationService.Entities;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace AuthenticationService.Tests.Helpers;

/// <summary>
/// Test-only subclass of <see cref="DatabaseContext"/> that papers over SQLite quirks.
/// SQLite stores DateTimeOffset as TEXT and can't translate comparisons / ORDER BY on it
/// — so we register value converters that map every DateTimeOffset property to UtcTicks,
/// an Int64 column SQLite handles natively. Production providers (MySQL / SqlServer /
/// PostgreSQL) all have proper DateTimeOffset support and don't see this converter.
/// </summary>
internal sealed class TestDatabaseContext : DatabaseContext
{
    public TestDatabaseContext(DbContextOptions options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        var nonNull = new ValueConverter<DateTimeOffset, long>(
            v => v.UtcTicks,
            v => new DateTimeOffset(v, TimeSpan.Zero));

        var nullable = new ValueConverter<DateTimeOffset?, long?>(
            v => v.HasValue ? v.Value.UtcTicks : null,
            v => v.HasValue ? new DateTimeOffset(v.Value, TimeSpan.Zero) : null);

        // IdentityUser.LockoutEnd — was here before the wider refactor, keep it.
        builder.Entity<User>().Property(u => u.LockoutEnd).HasConversion(nullable);
        builder.Entity<User>().Property(u => u.CreatedAt).HasConversion(nonNull);

        builder.Entity<RefreshToken>().Property(r => r.CreatedAt).HasConversion(nonNull);
        builder.Entity<RefreshToken>().Property(r => r.ExpiresAt).HasConversion(nonNull);
        builder.Entity<RefreshToken>().Property(r => r.ConsumedAt).HasConversion(nullable);

        builder.Entity<RevokedToken>().Property(r => r.ExpiresAt).HasConversion(nullable);
        builder.Entity<RevokedToken>().Property(r => r.RevokedAt).HasConversion(nullable);
        builder.Entity<RevokedToken>().Property(r => r.WarnedAt).HasConversion(nullable);
        builder.Entity<RevokedToken>().Property(r => r.LockedAt).HasConversion(nullable);

        builder.Entity<RevokedTokenAccessAttempt>().Property(r => r.CreatedAt).HasConversion(nonNull);

        builder.Entity<SecurityEvent>().Property(s => s.Timestamp).HasConversion(nonNull);

        builder.Entity<Client>().Property(c => c.CreatedAt).HasConversion(nonNull);
        builder.Entity<Client>().Property(c => c.LastUsedAt).HasConversion(nullable);

        // Multi-tenancy Phase 1 entities.
        builder.Entity<Tenant>().Property(t => t.CreatedAt).HasConversion(nonNull);
        builder.Entity<Tenant>().Property(t => t.SuspendedAt).HasConversion(nullable);
        builder.Entity<Tenant>().Property(t => t.PendingDeletionAt).HasConversion(nullable);
        builder.Entity<UserTenantMembership>().Property(m => m.CreatedAt).HasConversion(nonNull);
        builder.Entity<UserTenantMembership>().Property(m => m.RemovedAt).HasConversion(nullable);
        builder.Entity<UserTenantMembershipRole>().Property(r => r.AssignedAt).HasConversion(nonNull);
    }
}
