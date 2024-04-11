using Skuzzle.Core.Service.AuthenticationService.Storage.Attributes;
using Skuzzle.Core.Service.AuthenticationService.Storage.Migrations;
using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Service.AuthenticationService.Storage.Entities;

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
    public string FirstName { get; set; } = string.Empty;

    [CompoundIndex(name: "person", direction: IndexDirection.ASCENDING)]
    [MaxLength(30)]
    public string LastName { get; set; } = string.Empty;

    [Phone]
    public string Phone { get; set; } = string.Empty;

    [MaxLength(30)]
    public string Country { get; set; } = string.Empty;

    public List<string> Roles { get; set; } = ["Unconfirmed User"];

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? UpdatedAt { get; set; }

    public int Version { get; set; } = EntityMigrationCurrentVersions.UserEntity;
}
