using Skuzzle.Core.Service.AuthenticationGateway.Dtos;
using Skuzzle.Core.Service.AuthenticationGateway.Models;

namespace Skuzzle.Core.Service.AuthenticationGateway.Extensions;

public interface IPasswordHashService
{
    (byte[] hash, byte[] salt) Create(string password);
    bool Verify(UserCredentialsDto userDto, User user);
}