using System.Linq.Expressions;

namespace Skuzzle.Core.Service.AuthenticationService.Storage;

public interface IRepository<TModel>
{
    Task InsertAsync(TModel document, CancellationToken ct = default);

    Task<List<TModel>> FindAsync(CancellationToken ct = default);

    Task<TModel?> FindAsync(Guid id, CancellationToken ct = default);
    Task<TModel?> FindAsync(Expression<Func<TModel, bool>> exp, CancellationToken ct = default);
    Task<List<TModel>> FindManyAsync(Expression<Func<TModel, bool>> exp, CancellationToken ct = default);

    Task DeleteAsync(Guid id, CancellationToken ct = default);

    Task UpdateAsync(TModel document, CancellationToken ct = default);
}
