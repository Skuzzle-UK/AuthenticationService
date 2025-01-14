using Microsoft.EntityFrameworkCore;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Services.Interfaces;
using Skuzzle.Core.Authentication.Service.Storage;
using Skuzzle.Core.Lib.ResultClass;

namespace Skuzzle.Core.Authentication.Service.Services;

public class UserService : IUserService
{
    private readonly IRepository<User> _repository;

    public UserService(IRepository<User> repository)
    {
        _repository = repository;
    }

    public async Task<Result> CreateAsync(User user, CancellationToken ct)
    {
        var result = await _repository.CreateAsync(user, ct);
        if (result.IsFailure)
        {
            return Result.Fail(result.Exception!, result.ErrorMessage);
        }

        return result;
    }

    public async Task<Result> DeleteAsync(Guid id, CancellationToken ct)
    {
        // TODO: Delete user should not delete but should actually set as inactive and delete sensitive data/nb
        var result = await _repository.DeleteAsync(id, ct);
        if (result.IsFailure)
        {
            return Result.Fail(result.Exception!, result.ErrorMessage);
        }

        return Result.Ok();
    }

    public async Task<Result<User>> GetById(Guid id, CancellationToken ct)
    {
        var result = await _repository.FindAsync(id, ct);
        if (result.IsFailure)
        {
            return Result.Fail<User>(result.Exception!, result.ErrorMessage);
        }

        return result;
    }

    public async Task<Result<User>> GetByUsername(string username, CancellationToken ct)
    {
        var result = await _repository.FirstOrDefaultAsync(o => o.Username.ToLower() == username.ToLower() || o.Email.ToLower() == username.ToLower(), ct);
        if (result.IsFailure)
        {
            return Result.Fail<User>(result.Exception!, result.ErrorMessage);
        }

        return result;
    }

    public async Task<Result> UpdateAsync(User user, CancellationToken ct)
    {
        var result = await _repository.UpdateAsync(user, ct);
        if (result.IsFailure)
        {
            return Result.Fail<User>(result.Exception!, result.ErrorMessage);
        }

        return result;
    }
}
