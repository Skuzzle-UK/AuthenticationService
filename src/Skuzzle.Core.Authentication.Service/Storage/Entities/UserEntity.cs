using Skuzzle.Core.Authentication.Service.Storage.Attributes;
using Skuzzle.Core.Authentication.Service.Storage.Migrations;
using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Authentication.Service.Storage.Entities;

public class UserEntity : IEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Index(unique: true)]
    [Required]
    [MinLength(4)]
    [MaxLength(20)]
    public string Username { get; set; } = string.Empty;

    public required byte[] Hash { get; set; }

    public required byte[] Salt { get; set; }

    [Index(unique: true)]
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [CompoundIndex(name: "person", direction: IndexDirection.ASCENDING)]
    [MaxLength(30)]
    [Encrypt]
    public string FirstName { get; set; } = string.Empty;

    [CompoundIndex(name: "person", direction: IndexDirection.ASCENDING)]
    [MaxLength(30)]
    [Encrypt]
    public string LastName { get; set; } = string.Empty;

    [Phone]
    [Encrypt]
    public string Phone { get; set; } = string.Empty;

    [MaxLength(30)]
    [Encrypt]
    public string Country { get; set; } = string.Empty;

    [Encrypt]
    public string Roles { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? UpdatedAt { get; set; }

    public int Version { get; set; } = EntityMigrationCurrentVersions.UserEntity;
}
