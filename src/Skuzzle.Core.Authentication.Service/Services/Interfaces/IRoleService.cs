using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Lib.ResultClass;

namespace Skuzzle.Core.Authentication.Service.Services.Interfaces;

public interface IRoleService
{
    Task<Result> CreateAsync(Role role, CancellationToken ct);

    Task<Result> UpdateAsync(Role role, CancellationToken ct);

    Task<Result> DeleteAsync(Guid id, CancellationToken ct);

    Task<Result<Role>> GetById(Guid id, CancellationToken ct);

    Task<Result<IEnumerable<Role>>> GetAll(CancellationToken ct);
}
