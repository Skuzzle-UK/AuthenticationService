using AuthenticationService.Entities;
using AuthenticationService.Storage.Seed;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Storage;

public class DatabaseContext : IdentityDbContext<User, Role, string>
{
    public DatabaseContext(DbContextOptions options) : base(options)
    {

    }

    public DbSet<RevokedToken> RevokedTokens { get; set; }
    public DbSet<AccessRecord> AccessRecords { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfiguration(new RoleConfiguration());

        builder.Entity<RevokedToken>(entity =>
        {
            entity.HasKey(e => e.TokenJti);
            entity.Property(e => e.TokenJti).IsRequired();
        });

        builder.Entity<AccessRecord>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.TokenJti).IsRequired();
            entity.HasIndex(e => e.TokenJti);
        });
    }
}
