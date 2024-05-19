namespace Skuzzle.Core.Authentication.Service.Storage.Entities;

public interface IEncryptedEntity : IEntity
{
    public string EncryptedData {  get; set; }
}
