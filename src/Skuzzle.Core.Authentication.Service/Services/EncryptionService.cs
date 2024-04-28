using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Skuzzle.Core.Authentication.Service.Settings;
using System.Security.Cryptography;
using System.Text;

namespace Skuzzle.Core.Authentication.Service.Services;

public class EncryptionService : IEncryptionService
{
    private readonly EncryptionSettings _settings;

    public EncryptionService(IOptions<EncryptionSettings> settings)
    {
        _settings = settings.Value;
    }

    public T? Decrypt<T>(string encryptedString)
    {
        var cipherText = Convert.FromBase64String(encryptedString);

        using var aes = Aes.Create();
        aes.Key = _settings.Key;
        aes.IV = _settings.InitialisationVector;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();

        var decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
        var decryptedJson = Encoding.UTF8.GetString(decryptedBytes);

        return JsonConvert.DeserializeObject<T>(decryptedJson);
    }

    public string Encrypt<T>(T input)
    {
        var dataToEncrypt = JsonConvert.SerializeObject(input);

        using var aes = Aes.Create();
        aes.Key = _settings.Key;
        aes.IV = _settings.InitialisationVector;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();

        var bytes = Encoding.UTF8.GetBytes(dataToEncrypt);
        var cipherText = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);

        return Convert.ToBase64String(cipherText);
    }
}
