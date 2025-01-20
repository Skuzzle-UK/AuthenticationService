using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Lib.ResultClass;

namespace Skuzzle.Core.Authentication.Client;
public interface IAuthenticationClient
{
    Task<Result> RegisterUserAsync(UserDto user, CancellationToken ct);
    Task<Result<Token>> GetTokenAsync(Guid userId, CancellationToken ct = default);
    Task<Result<Token>> GetTokenAsync(AuthenticationRequest request, CancellationToken ct = default);
    Result InvalidateToken(Guid userId, CancellationToken ct = default);
    Task<Result> IsTokenValidAsync(Guid userId, CancellationToken ct = default);
}