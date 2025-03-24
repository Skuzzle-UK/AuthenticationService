using AuthenticationService.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthenticationService.SeedConfiguration;

public class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    public void Configure(EntityTypeBuilder<Role> builder)
    {
        builder.HasData(
            new Role
            {
                Id = Guid.NewGuid().ToString(),
                Name = "Visitor",
                NormalizedName = "VISITOR",
                Description = "The visitor role for the user"
            },
            new Role
            {
                Id = Guid.NewGuid().ToString(),
                Name = "Admin",
                NormalizedName = "ADMIN",
                Description = "Regular admin role"
            }
        );
    }
}
