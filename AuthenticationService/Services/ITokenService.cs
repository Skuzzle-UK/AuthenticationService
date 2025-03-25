using AuthenticationService.Entities;

namespace AuthenticationService.Services;

public interface ITokenService
{
    string CreateToken(User user, IList<string> roles);
}
