using Skuzzle.Core.Service.AuthenticationService.Storage.Attributes;
using Skuzzle.Core.Service.AuthenticationService.Storage.Migrations;
using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Service.AuthenticationService.Storage.Entities;

// TODO Pop UserEntity into an encrypted repo here's a suggestion:
/*password encryption bash script
    echo -n "UnencryptedPassword" > input.txt

    key='ac06487adaedae424878915aac1234567897aacab422a7272a0a04ff4aa13145'

    ivec='1aa1cd4f56787ba787a78ddc9e108ae2'
 
    encoded=$(openssl enc -aes-256-cbc -nosalt -e \
        -in input.txt \
        -K $key -iv $ivec | openssl base64)

    echo $encoded*/

/*public class Encrypter
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public Encrypter(string keyString, string ivString)
    {
        _key = Convert.FromHexString(keyString);
        _iv = Convert.FromHexString(ivString);
    }

    public string EncryptString(string text)
    {
        var plainText = Encoding.UTF8.GetBytes(text);

        using var aesAlg = Aes.Create();
        using var encryptor = aesAlg.CreateEncryptor(_key, _iv);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        {
            csEncrypt.Write(plainText, 0, plainText.Length);
        }

        var cipherText = msEncrypt.ToArray();

        return Convert.ToBase64String(cipherText);
    }

    public string DecryptString(string cipherText)
    {
        var fullCipher = Convert.FromBase64String(cipherText);

        using var aesAlg = Aes.Create();
        using var decryptor = aesAlg.CreateDecryptor(_key, _iv);
        using var msDecrypt = new MemoryStream();
        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
        {
            csDecrypt.Write(fullCipher, 0, fullCipher.Length);
        }

        var plaintext = msDecrypt.ToArray();
        return Encoding.UTF8.GetString(plaintext);
    }
}*/

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
