namespace Skuzzle.Core.Authentication.Service.Services.Interfaces;

public interface IEncryptionService
{
    string Encrypt<T>(T input);
    T? Decrypt<T>(string encryptedData);
}
