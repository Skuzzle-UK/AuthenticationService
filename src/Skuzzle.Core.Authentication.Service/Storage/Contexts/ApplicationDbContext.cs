using Microsoft.EntityFrameworkCore;
using Skuzzle.Core.Authentication.Service.Storage.Entities;

namespace Skuzzle.Core.Authentication.Service.Storage.Contexts;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }

    public static void ApplyMigrations(IApplicationBuilder app)
    {
        using (var serviceScope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope())
        {
            var context = serviceScope.ServiceProvider.GetService<ApplicationDbContext>();
            context!.Database.Migrate();
        }
    }

    public DbSet<UserEntity> Users { get; set; }
    public DbSet<RoleEntity> Roles { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<UserEntity>()
            .HasIndex(o => o.Username)
            .IsUnique();

        modelBuilder.Entity<UserEntity>()
            .HasIndex(o => o.Email)
            .IsUnique();

        modelBuilder.Entity<RoleEntity>()
            .HasIndex(o => o.Name)
            .IsUnique();
    }
}
