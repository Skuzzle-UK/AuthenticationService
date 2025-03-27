using AuthenticationService.Entities;
using AuthenticationService.Shared.Models;
using System.Security.Claims;

namespace AuthenticationService.Services;

public interface ITokenService
{
    Task<Token> CreateTokenAsync(User user, IList<string> roles);
    Task<bool> ValidateExpiredToken(string token);
}
