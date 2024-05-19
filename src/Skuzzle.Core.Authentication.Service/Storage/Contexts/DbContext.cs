using Skuzzle.Core.Authentication.Service.Storage.Entities;
using Skuzzle.Core.Lib.MongoDb.Builder;
using Skuzzle.Core.Lib.MongoDb.Configuration;
using Skuzzle.Core.Lib.MongoDb.Context;

namespace Skuzzle.Core.Authentication.Service.Storage.Contexts;

public class DbContext : MongoDbContext
{
    public DbContext(IMongoDbConfiguration config)
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
            .HasIndex(o => o.Username)
            .HasIndex(o => o.Email)
            .ToCollection("users");
    }
}