using AuthenticationService.Entities;
using AuthenticationService.Shared.Constants;
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
                Name = RolesConstants.Admin,
                NormalizedName = RolesConstants.Normalised.Admin,
                Description = "Overall admin role",
                ConcurrencyStamp = "0971cc17-84a5-44fb-b773-1b7fd4e58c38"
            },
            new Role
            {
                Id = "2b3ad022-d787-4e96-9a59-55b286a6e482",
                Name = RolesConstants.DefaultUser,
                NormalizedName = RolesConstants.Normalised.DefaultUser,
                Description = "Default user role",
                ConcurrencyStamp = "ab5a8990-8062-41ea-b0ce-395599973a36"
            },
            new Role
            {
                Id = "8a0c1c8b-7e1f-4a31-9c8b-2f0aa9e5a701",
                Name = RolesConstants.PlatformAdmin,
                NormalizedName = RolesConstants.Normalised.PlatformAdmin,
                Description = "Platform-level tenant administration (multi-tenancy Decision 5).",
                ConcurrencyStamp = "5d2c1d4f-9b0a-4f2c-8b0d-7e1a4a9d2c3b"
            }
        );
    }
}
