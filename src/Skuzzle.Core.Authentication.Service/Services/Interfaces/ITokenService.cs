using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Lib.ResultClass;
using System.Security.Claims;

namespace Skuzzle.Core.Authentication.Service.Services.Interfaces;

public interface ITokenService
{
    Token GetNewToken(User user);
    Token? RefreshToken(User user, string refreshToken);
    Result<ClaimsPrincipal> ValidateToken(string token, bool validateLifetime);
}
