using Skuzzle.Core.Authentication.Lib.Models;
using System.Security.Claims;

namespace Skuzzle.Core.Authentication.Service.Services;

public interface ITokenService
{
    Token GetNewToken(User user);
    Token? RefreshToken(User user, string refreshToken);
    ClaimsPrincipal ValidateToken(string token, bool validateLifetime);
}
