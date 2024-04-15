namespace Skuzzle.Core.Service.AuthenticationService.Services;

public interface IEncryptionService
{
    string Encrypt<T>(T input);
    T? Decrypt<T>(string encryptedData);
}
