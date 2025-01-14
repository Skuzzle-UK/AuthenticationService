using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Services.Interfaces;
using Skuzzle.Core.Authentication.Service.Storage;
using Skuzzle.Core.Lib.ResultClass;

namespace Skuzzle.Core.Authentication.Service.Services;

// TODO: Complete this /nb
public class RoleService : IRoleService
{
    private readonly IRepository<Role> _repository;

    public RoleService(IRepository<Role> repository)
    {
        _repository = repository;
    }

    public async Task<Result> CreateAsync(Role role, CancellationToken ct)
    {
        var result = await _repository.CreateAsync(role, ct);
        if (result.IsFailure)
        {
            return Result.Fail(result.Exception!, result.ErrorMessage);
        }

        return result;
    }

    public async Task<Result> DeleteAsync(Guid id, CancellationToken ct)
    {
        // TODO: Delete should not delete but should actually set as inactive /nb
        var result = await _repository.DeleteAsync(id, ct);
        if (result.IsFailure)
        {
            return Result.Fail(result.Exception!, result.ErrorMessage);
        }

        return Result.Ok();
    }

    public Task<Result<IEnumerable<Role>>> GetAll(CancellationToken ct)
    {
        throw new NotImplementedException();
    }

    public async Task<Result<Role>> GetById(Guid id, CancellationToken ct)
    {
        var result = await _repository.FindAsync(id, ct);
        if (result.IsFailure)
        {
            return Result.Fail<Role>(result.Exception!, result.ErrorMessage);
        }

        return result;
    }

    public async Task<Result> UpdateAsync(Role role, CancellationToken ct)
    {
        var result = await _repository.UpdateAsync(role, ct);
        if (result.IsFailure)
        {
            return Result.Fail<User>(result.Exception!, result.ErrorMessage);
        }

        return result;
    }
}
