using System.Security.Cryptography;
using Skuzzle.Core.Authentication.Service.Services.Interfaces;

namespace Skuzzle.Core.Authentication.Service.Extensions;

public class PasswordHashService : IPasswordHashService
{
    public (byte[] hash, byte[] salt) Create(string password)
    {
        using var hmac = new HMACSHA512();
        var salt = hmac.Key;
        var hash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

        return (hash, salt);
    }

    public bool Verify(string password, byte[] hash, byte[] salt)
    {
        using var hmac = new HMACSHA512(salt);
        var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        return computedHash.SequenceEqual(hash);
    }
}
