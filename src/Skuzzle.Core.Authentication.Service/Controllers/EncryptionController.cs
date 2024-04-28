using Microsoft.AspNetCore.Mvc;
using Skuzzle.Core.Authentication.Service.Services;
using System.Security.Cryptography;

namespace Skuzzle.Core.Authentication.Service.Controllers;

[Route("api/[controller]")]
[ApiController]
public class EncryptionController : ControllerBase
{
    private readonly IEncryptionService _encrypterService;

    public EncryptionController(IEncryptionService encrypterService)
    {
        _encrypterService = encrypterService;
    }

    [HttpGet]
    public async Task<ActionResult<string>> Encrypt()
    {
        var testObject = new TestObject()
        {
            Number = 1,
            Name = "test",
            Value = "testing",
            IsIt = true
        };

        return _encrypterService.Encrypt(testObject);
    }

    [HttpPost]
    public async Task<ActionResult<TestObject?>> Decrypt(string encryptedData)
    {
        return _encrypterService.Decrypt<TestObject>(encryptedData);
    }

    [HttpGet("generate")]
    public async Task<ActionResult<string>> GenerateKeyAndIv()
    {
        // Generate a random key (256 bits = 32 bytes)
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        // Generate a random IV (16 bytes)
        byte[] iv = new byte[16];
        RandomNumberGenerator.Fill(iv);

        // Now you have a random key and IV
        return $"Random Key: {Convert.ToBase64String(key)} - Random IV: {Convert.ToBase64String(iv)}";
    }
}

public class TestObject
{
    public int Number { get; set; }
    public string Name { get; set; }
    public string Value { get; set; }
    public bool IsIt { get; set; }
}
