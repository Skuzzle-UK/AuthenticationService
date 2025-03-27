using AuthenticationService.Entities;
using AuthenticationService.Shared.Models;

namespace AuthenticationService.Services;

public interface ITokenService
{
    Task<Token> CreateTokenAsync(User user, IList<string> roles);
}
