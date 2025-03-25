using AuthenticationService.Entities;
using AuthenticationService.Shared.Models;

namespace AuthenticationService.Services;

public interface ITokenService
{
    Token CreateToken(User user, IList<string> roles);
}
