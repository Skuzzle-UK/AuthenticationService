using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Lib.ResultClass;

namespace Skuzzle.Core.Authentication.Service.Services.Interfaces;

public interface IUserService
{
    Task<Result> CreateAsync(User user, CancellationToken ct);

    Task<Result> UpdateAsync(User user, CancellationToken ct);

    Task<Result> DeleteAsync(Guid id, CancellationToken ct);

    Task<Result<User>> GetById(Guid id, CancellationToken ct);

    Task<Result<User>> GetByUsername(string username, CancellationToken ct);
}
