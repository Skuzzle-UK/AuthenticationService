using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AuthenticationService.Shared.Models;

namespace AuthenticationService.Services;

public interface ITokenService
{
    Task<Token> CreateTokenAsync(User user, IList<string> roles);
    Task<bool> ValidateExpiredTokenAsync(string token);
    Task RevokeTokenAsync(string token, string ipAddress);
    DateTime? GetExpiryDateTime(string token);
    string GetUserId(string token);
    Task<bool> IsRevokedAsync(string token);

    /// <summary>
    /// Records an access attempt. This method can be used for recording legitimate or revoked access attempts.
    /// </summary>
    /// <param name="token"></param>
    /// <param name="ipAddress"></param>
    /// <returns></returns>
    Task RecordAccessAttemptAsync(string token, string ipAddress);
}
