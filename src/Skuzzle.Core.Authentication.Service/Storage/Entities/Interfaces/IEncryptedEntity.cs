namespace Skuzzle.Core.Authentication.Service.Storage.Entities.Interfaces;

public interface IEncryptedEntity : IEntity
{
    public string EncryptedData { get; set; }
}
