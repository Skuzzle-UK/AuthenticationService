namespace Skuzzle.Core.Authentication.Service.Services;

public interface IEncryptionService
{
    string Encrypt<T>(T input);
    T? Decrypt<T>(string encryptedData);
}
