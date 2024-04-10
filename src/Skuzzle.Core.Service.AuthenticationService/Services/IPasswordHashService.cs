using Skuzzle.Core.Service.AuthenticationService.Dtos;
using Skuzzle.Core.Service.AuthenticationService.Models;

namespace Skuzzle.Core.Service.AuthenticationService.Extensions;

public interface IPasswordHashService
{
    (byte[] hash, byte[] salt) Create(string password);
    bool Verify(UserCredentialsDto userDto, User user);
}