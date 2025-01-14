using Skuzzle.Core.Authentication.Service.Storage.Entities;
using Skuzzle.Core.Lib.MongoDb.Builder;
using Skuzzle.Core.Lib.MongoDb.Configuration;
using Skuzzle.Core.Lib.MongoDb.Context;

namespace Skuzzle.Core.Authentication.Service.Storage.Contexts;

public class ApplicationMongoDbContext : MongoDbContext
{
    public ApplicationMongoDbContext(IMongoDbConfiguration config)
        : base(config)
    {
    }

    protected override void OnConfiguration(ModelBuilder builder)
    {
        builder
            .UseCaseInsensitiveCompare()
            .UseStringEnums();

        builder
            .Entity<UserEntity>()
            .HasKey(o => o.Id)
            .HasIndex(o => o.Username, isUnique: true)
            .HasIndex(o => o.Email, isUnique: true)
            .ToCollection("users");

        builder
            .Entity<RoleEntity>()
            .HasKey(o => o.Id)
            .HasIndex(o => o.Name, isUnique: true)
            .ToCollection("Roles");
    }
}