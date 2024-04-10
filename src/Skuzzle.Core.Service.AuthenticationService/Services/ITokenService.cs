using Skuzzle.Core.Service.AuthenticationService.Models;

namespace Skuzzle.Core.Service.AuthenticationService.Services;

public interface ITokenService
{
    string GetNewToken(User user);
}
