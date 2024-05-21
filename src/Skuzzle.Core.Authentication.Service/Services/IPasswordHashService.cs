using Skuzzle.Core.Authentication.Lib.Models;

namespace Skuzzle.Core.Authentication.Service.Extensions;

public interface IPasswordHashService
{
    (byte[] hash, byte[] salt) Create(string password);
    bool Verify(string password, byte[] hash, byte[] salt);
}