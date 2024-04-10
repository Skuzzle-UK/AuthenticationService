namespace Skuzzle.Core.Service.AuthenticationGateway.Storage.Entities;

public interface IEntity
{
    public Guid Id { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
}