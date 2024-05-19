using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace Skuzzle.Core.Authentication.Service.Controllers;

[Route("api/[controller]")]
[ApiController]
public class EncryptionController : ControllerBase
{

    public EncryptionController()
    {
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