using AuthenticationService.Entities;
using AuthenticationService.Shared.Models;

namespace AuthenticationService.Services;

public interface ITokenService
{
    Task<Token> CreateTokenAsync(User user, IList<string> roles);
    Task<bool> ValidateExpiredTokenAsync(string token);
    Task RevokeTokenAsync(string token, string ipAddress);
    DateTime? GetExpiryDateTime(string token);
    string GetUserName(string token);
    Task<bool> IsRevokedAsync(string token);
    Task AddAccessAttemptAsync(string token, string ipAddress);
}
