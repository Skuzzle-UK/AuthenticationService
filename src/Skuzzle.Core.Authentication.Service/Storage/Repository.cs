using AutoMapper;
using Microsoft.EntityFrameworkCore;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Storage.Contexts;
using Skuzzle.Core.Authentication.Service.Storage.Entities.Interfaces;
using Skuzzle.Core.Lib.ResultClass;
using System.Linq.Expressions;

namespace Skuzzle.Core.Authentication.Service.Storage;

public class Repository<TModel, TEntity> : IRepository<TModel>
    where TModel : class, IModel
    where TEntity : class, IEntity
{
    private readonly ILogger<Repository<TModel, TEntity>> _logger;
    private readonly ApplicationDbContext _context;
    private readonly DbSet<TEntity> _dbSet;
    private readonly IMapper _mapper;

    public Repository(
        ILogger<Repository<TModel, TEntity>> logger,
        ApplicationDbContext context,
        IMapper mapper)
    {
        _logger = logger;
        _context = context;
        _mapper = mapper;

        _dbSet = _context.Set<TEntity>();
    }

    public Task<Result<bool>> CountAsync(CancellationToken ct = default) =>
        throw new NotImplementedException();
    

    public async Task<Result> CreateAsync(TModel data, CancellationToken ct = default)
    {
        try
        {
            var entity = _mapper.Map<TEntity>(data);
            entity.CreatedAt = DateTimeOffset.UtcNow;

            await _dbSet.AddAsync(entity);
            await _context.SaveChangesAsync();

            return Result.Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Document creation failed with error: {ErrorMessage}", ex.Message);
            return Result.Fail<TModel>(ex, "Document creation failed with error: {ErrorMessage}", ex.Message);
        }
    }

    public Task<Result<bool>> DeleteAsync(Guid id, CancellationToken ct = default) =>
        throw new NotImplementedException();

    public async Task<Result<TModel>> FindAsync(Guid id, CancellationToken ct = default)
    {
        try
        {
            var entity = await _dbSet.FindAsync(id, ct);
            if (entity is null)
            {
                return Result.Ok<TModel>(default);
            }

            var model = _mapper.Map<TModel>(entity);
            if (model is null)
            {
                return Result.Fail<TModel>("Model is null");
            }

            return Result.Ok(model);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred retrieving document with error {ErrorMessage}", ex.Message);
            return Result.Fail<TModel>(ex, "Error occurred retrieving document with error {ErrorMessage}", ex.Message);
        }
    }

    public async Task<Result<TModel>> FirstOrDefaultAsync(Expression<Func<TModel, bool>> predicate, CancellationToken ct = default)
    {
        try
        {
            var mappedExpression = _mapper.Map<Expression<Func<TEntity, bool>>>(predicate);

            var entity = await _dbSet.FirstOrDefaultAsync(mappedExpression, ct);
            if (entity is null)
            {
                return Result.Ok<TModel>(default);
            }

            var model = _mapper.Map<TModel>(entity);
            if (model is null)
            {
                return Result.Ok<TModel>(default);
            }

            return Result.Ok(model);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred retrieving document with error {ErrorMessage}", ex.Message);
            return Result.Fail<TModel>(ex, "Error occurred retrieving document with error {ErrorMessage}", ex.Message);
        }
    }

    public Task<Result<IEnumerable<TModel>>> GetAllAsync(CancellationToken ct = default) =>
        throw new NotImplementedException();

    public Task<Result<IEnumerable<TModel>>> GetAsync(Expression<Func<TModel, bool>> predicate, CancellationToken ct = default) =>
        throw new NotImplementedException();

    public Task<Result<IEnumerable<Guid>>> GetIdsAsync(Expression<Func<TModel, bool>> predicate, CancellationToken ct = default) =>
        throw new NotImplementedException();

    public Task<Result<TModel>> UpdateAsync(TModel data, CancellationToken ct = default) =>
        throw new NotImplementedException();
}
