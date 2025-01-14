namespace Skuzzle.Core.Authentication.Service.Storage.Entities.Interfaces;

public interface IEntity
{
    public Guid Id { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? UpdatedAt { get; set; }

    public int Version { get; set; }
}