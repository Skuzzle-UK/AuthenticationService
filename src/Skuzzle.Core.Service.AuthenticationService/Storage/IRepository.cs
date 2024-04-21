using Skuzzle.Core.Lib.ResultClass;
using System.Linq.Expressions;

namespace Skuzzle.Core.Service.AuthenticationService.Storage;

public interface IRepository<TModel>
{
    Task<Result> InsertAsync(TModel document, CancellationToken ct = default);

    Task<Result<List<TModel>>> FindAsync(CancellationToken ct = default);

    Task<Result<TModel>> FindAsync(Guid id, CancellationToken ct = default);

    Task<Result<TModel>> FindAsync(Expression<Func<TModel, bool>> exp, CancellationToken ct = default);

    Task<Result<List<TModel>>> FindManyAsync(Expression<Func<TModel, bool>> exp, CancellationToken ct = default);

    Task<Result> DeleteAsync(Guid id, CancellationToken ct = default);

    Task<Result> UpdateAsync(TModel document, CancellationToken ct = default);
}
