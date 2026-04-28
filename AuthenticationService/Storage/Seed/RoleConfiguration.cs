using AuthenticationService.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthenticationService.Storage.Seed;

public class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    public void Configure(EntityTypeBuilder<Role> builder)
    {
        builder.HasData(
            new Role
            {
                Id = "c6c93b9b-7e04-4812-8395-7b2eaad474da",
                Name = "Admin",
                NormalizedName = "ADMIN",
                Description = "Regular admin role",
                ConcurrencyStamp = "0971cc17-84a5-44fb-b773-1b7fd4e58c38"
            },
            new Role
            {
                Id = "2b3ad022-d787-4e96-9a59-55b286a6e482",
                Name = "User",
                NormalizedName = "User",
                Description = "Regular user role",
                ConcurrencyStamp = "ab5a8990-8062-41ea-b0ce-395599973a36"
            }
        );
    }
}
