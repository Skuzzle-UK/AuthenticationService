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

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfiguration(new RoleConfiguration());

        var dateOnlyToNullableDateTime = new ValueConverter<DateOnly?, DateTime?>(
            d => d.HasValue ? d.Value.ToDateTime(TimeOnly.MinValue) : null,
            d => d.HasValue ? DateOnly.FromDateTime(d.Value) : null);

        builder.Entity<User>()
            .Property(u => u.DateOfBirth)
            .HasConversion(dateOnlyToNullableDateTime);

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
    }
}
