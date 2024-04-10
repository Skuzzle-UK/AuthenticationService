using Skuzzle.Core.Service.AuthenticationGateway.Storage.Attributes;
using Skuzzle.Core.Service.AuthenticationGateway.Storage.Migrations;
using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Service.AuthenticationGateway.Storage.Entities;

public class UserEntity : IEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Index(unique: true)]
    public string Username { get; set; } = string.Empty;

    public required byte[] Hash { get; set; }

    public required byte[] Salt { get; set; }

    [Index(unique: true)]
    public required string Email { get; set; }

    public string FirstName { get; set; } = string.Empty;

    public string LastName { get; set; } = string.Empty;

    public string Phone { get; set; } = string.Empty;

    public string Country { get; set; } = string.Empty;

    public List<string> Roles { get; set; } = ["Unconfirmed User"];

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? UpdatedAt { get; set; }

    public int Version { get; set; } = EntityMigrationCurrentVersions.UserEntity;
}
