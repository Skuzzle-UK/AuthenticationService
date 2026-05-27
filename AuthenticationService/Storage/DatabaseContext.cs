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

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfiguration(new RoleConfiguration());

        // DateOnly converter is a MySQL-only workaround. Oracle's MySql.EntityFrameworkCore
        // can't translate DateOnly natively.
        if (Database.IsMySql())
        {
            var dateOnlyToNullableDateTime = new ValueConverter<DateOnly?, DateTime?>(
                d => d.HasValue ? d.Value.ToDateTime(TimeOnly.MinValue) : null,
                d => d.HasValue ? DateOnly.FromDateTime(d.Value) : null);

            builder.Entity<User>()
                .Property(u => u.DateOfBirth)
                .HasConversion(dateOnlyToNullableDateTime);
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
    }
}
