﻿using Skuzzle.Core.Authentication.Service.Storage.Entities.Interfaces;
using Skuzzle.Core.Authentication.Service.Storage.Migrations;
using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Authentication.Service.Storage.Entities;

public class UserEntity : IEncryptedEntity
{
    [Key]
    public required Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MinLength(4)]
    [MaxLength(20)]
    public required string Username { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    public string EncryptedData { get; set; } = string.Empty;

    [Required]
    public required DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? UpdatedAt { get; set; }

    [Required]
    public required int Version { get; set; } = EntityMigrationCurrentVersions.UserEntity;
}
