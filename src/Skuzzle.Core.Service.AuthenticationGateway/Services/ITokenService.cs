using Skuzzle.Core.Service.AuthenticationGateway.Models;

namespace Skuzzle.Core.Service.AuthenticationGateway.Services;

public interface ITokenService
{
    string GetNewToken(User user);
}
