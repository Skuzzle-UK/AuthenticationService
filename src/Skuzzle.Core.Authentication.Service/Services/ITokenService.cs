using Skuzzle.Core.Authentication.Lib.Models;

namespace Skuzzle.Core.Authentication.Service.Services;

public interface ITokenService
{
    Token GetNewToken(User user);
    Token RefreshToken(string refreshToken);
}
