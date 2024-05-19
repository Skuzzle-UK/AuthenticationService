using Skuzzle.Core.Lib.ResultClass;
using System.Linq.Expressions;

namespace Skuzzle.Core.Authentication.Service.Storage;

public interface IRepository<TModel> where TModel : class
{
    Task<Result<IEnumerable<TModel>>> GetAllAsync(CancellationToken ct = default);

    Task<Result<IEnumerable<TModel>>> GetAsync(Expression<Func<TModel, bool>> predicate, CancellationToken ct = default);

    Task<Result<IEnumerable<Guid>>> GetIdsAsync(Expression<Func<TModel, bool>> predicate, CancellationToken ct = default);

    Task<Result<TModel>> FindAsync(Guid id, CancellationToken ct = default);

    Task<Result<TModel>> FirstOrDefaultAsync(Expression<Func<TModel, bool>> predicate, CancellationToken ct = default);

    Task<Result> CreateAsync(TModel data, CancellationToken ct = default);

    Task<Result<TModel>> UpdateAsync(TModel data, CancellationToken ct = default);

    Task<Result<bool>> DeleteAsync(Guid id, CancellationToken ct = default);

    Task<Result<bool>> CountAsync(CancellationToken ct = default);
}
