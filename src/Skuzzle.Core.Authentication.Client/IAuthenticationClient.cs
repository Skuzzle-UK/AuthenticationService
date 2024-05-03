using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Lib.ResultClass;

namespace Skuzzle.Core.Authentication.Client;
public interface IAuthenticationClient
{
    Task<Result<Token>> TryGetExistingTokenAsync(Guid userId);

    Task<Result<Token>> GetNewTokenAsync(AuthenticationRequest request);
}