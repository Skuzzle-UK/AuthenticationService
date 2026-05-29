using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Storage.Seed;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace AuthenticationService.Storage;

public class DatabaseContext : IdentityDbContext<User, Role, string>
{
    public DatabaseContext(DbContextOptions options) : base(options)
    {

    }

    public DbSet<RevokedToken> RevokedTokens { get; set; }
    public DbSet<RevokedTokenAccessAttempt> RevokedTokenAccessAttempts { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    public DbSet<SecurityEvent> SecurityEvents { get; set; }
    public DbSet<Client> Clients { get; set; }
    public DbSet<ClientScope> ClientScopes { get; set; }

    // Multi-tenancy Phase 1: Tenants + memberships. No TenantId on the entities
    // above yet — that's Phase 2.
    public DbSet<Tenant> Tenants { get; set; }
    public DbSet<UserTenantMembership> UserTenantMemberships { get; set; }
    public DbSet<UserTenantMembershipRole> UserTenantMembershipRoles { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfiguration(new RoleConfiguration());

        if (Database.IsMySql())
        {
            // DateOnly converter is a MySQL-only workaround. Oracle's MySql.EntityFrameworkCore
            // can't translate DateOnly natively.
            var dateOnlyToNullableDateTime = new ValueConverter<DateOnly?, DateTime?>(
                d => d.HasValue ? d.Value.ToDateTime(TimeOnly.MinValue) : null,
                d => d.HasValue ? DateOnly.FromDateTime(d.Value) : null);

            builder.Entity<User>()
                .Property(u => u.DateOfBirth)
                .HasConversion(dateOnlyToNullableDateTime);

            // Oracle's MySQL provider defaults DateTimeOffset columns to plain `datetime`
            // (second precision). Pin to datetime(6) to preserve sub-second precision —
            // matches the pre-refactor schema and keeps token/audit timestamps high-res.
            // SqlServer maps to native `datetimeoffset` (already μs); Postgres to
            // `timestamptz` (also μs); only MySQL needs this hint.
            ConfigureMySqlDateTimeOffsetPrecision<User>(builder, u => u.CreatedAt);
            ConfigureMySqlDateTimeOffsetPrecision<RefreshToken>(builder, r => r.CreatedAt);
            ConfigureMySqlDateTimeOffsetPrecision<RefreshToken>(builder, r => r.ExpiresAt);
            ConfigureMySqlDateTimeOffsetPrecision<RefreshToken>(builder, r => r.ConsumedAt);
            ConfigureMySqlDateTimeOffsetPrecision<RevokedToken>(builder, r => r.ExpiresAt);
            ConfigureMySqlDateTimeOffsetPrecision<RevokedToken>(builder, r => r.RevokedAt);
            ConfigureMySqlDateTimeOffsetPrecision<RevokedToken>(builder, r => r.WarnedAt);
            ConfigureMySqlDateTimeOffsetPrecision<RevokedToken>(builder, r => r.LockedAt);
            ConfigureMySqlDateTimeOffsetPrecision<RevokedTokenAccessAttempt>(builder, r => r.CreatedAt);
            ConfigureMySqlDateTimeOffsetPrecision<SecurityEvent>(builder, s => s.Timestamp);
            ConfigureMySqlDateTimeOffsetPrecision<Client>(builder, c => c.CreatedAt);
            ConfigureMySqlDateTimeOffsetPrecision<Client>(builder, c => c.LastUsedAt);

            // Multi-tenancy Phase 1.
            ConfigureMySqlDateTimeOffsetPrecision<Tenant>(builder, t => t.CreatedAt);
            ConfigureMySqlDateTimeOffsetPrecision<Tenant>(builder, t => t.SuspendedAt);
            ConfigureMySqlDateTimeOffsetPrecision<Tenant>(builder, t => t.PendingDeletionAt);
            ConfigureMySqlDateTimeOffsetPrecision<UserTenantMembership>(builder, m => m.CreatedAt);
            ConfigureMySqlDateTimeOffsetPrecision<UserTenantMembership>(builder, m => m.RemovedAt);
            ConfigureMySqlDateTimeOffsetPrecision<UserTenantMembershipRole>(builder, r => r.AssignedAt);
        }

        builder.Entity<RevokedToken>(entity =>
        {
            entity.HasKey(e => e.TokenJti);
            entity.Property(e => e.TokenJti).IsRequired();
        });

        builder.Entity<RevokedTokenAccessAttempt>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.TokenJti).IsRequired();
            entity.HasIndex(e => e.TokenJti);
        });

        builder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.Property(e => e.UserId).IsRequired();
            entity.Property(e => e.TokenHash).IsRequired();
            entity.HasIndex(e => e.TokenHash).IsUnique();
            entity.HasIndex(e => new { e.UserId, e.ConsumedAt });
            entity.HasIndex(e => e.FamilyId);
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<SecurityEvent>(entity =>
        {
            entity.HasKey(e => e.Id);
            // Composite descending index — the audit endpoint always filters by UserId
            // and orders by Timestamp DESC.
            entity.HasIndex(e => new { e.UserId, e.Timestamp });
            entity.HasIndex(e => e.EventId);
        });

        builder.Entity<Client>(entity =>
        {
            entity.HasKey(e => e.Id);
            // IsDisabled gets indexed — admin list-clients endpoint commonly filters by
            // active-only.
            entity.HasIndex(e => e.IsDisabled);
        });

        builder.Entity<ClientScope>(entity =>
        {
            entity.HasKey(e => e.Id);
            // Composite uniqueness: a client can only have one row per
            // (Audience, Scope) tuple. Trying to add the same scope twice should be a
            // no-op (or a 409 at the admin endpoint), never a duplicate row.
            entity.HasIndex(e => new { e.ClientId, e.Audience, e.Scope }).IsUnique();
            entity.HasIndex(e => e.ClientId);
            entity.HasOne(e => e.Client)
                  .WithMany(c => c.Scopes)
                  .HasForeignKey(e => e.ClientId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Multi-tenancy Phase 1.
        builder.Entity<Tenant>(entity =>
        {
            entity.HasKey(e => e.Id);
            // Name is the URL identifier and must be unique platform-wide.
            entity.HasIndex(e => e.Name).IsUnique();
            // Status is filtered on (e.g., listing all Active tenants) so worth indexing.
            entity.HasIndex(e => e.Status);
        });

        builder.Entity<UserTenantMembership>(entity =>
        {
            entity.HasKey(e => e.Id);
            // A user can have at most one membership per tenant — composite unique.
            entity.HasIndex(e => new { e.UserId, e.TenantId }).IsUnique();
            entity.HasIndex(e => e.TenantId);

            entity.HasOne(e => e.User)
                  .WithMany(u => u.Memberships)
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Tenant)
                  .WithMany(t => t.Memberships)
                  .HasForeignKey(e => e.TenantId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<UserTenantMembershipRole>(entity =>
        {
            // Composite primary key — a role assignment is (Membership, Role).
            entity.HasKey(e => new { e.MembershipId, e.RoleId });
            entity.HasIndex(e => e.RoleId);

            entity.HasOne(e => e.Membership)
                  .WithMany(m => m.RoleAssignments)
                  .HasForeignKey(e => e.MembershipId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.Role)
                  .WithMany()
                  .HasForeignKey(e => e.RoleId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
    }

    private static void ConfigureMySqlDateTimeOffsetPrecision<TEntity>(
        ModelBuilder builder,
        System.Linq.Expressions.Expression<Func<TEntity, DateTimeOffset?>> property)
        where TEntity : class
    {
        builder.Entity<TEntity>().Property(property).HasColumnType("datetime(6)");
    }

    private static void ConfigureMySqlDateTimeOffsetPrecision<TEntity>(
        ModelBuilder builder,
        System.Linq.Expressions.Expression<Func<TEntity, DateTimeOffset>> property)
        where TEntity : class
    {
        builder.Entity<TEntity>().Property(property).HasColumnType("datetime(6)");
    }
}
