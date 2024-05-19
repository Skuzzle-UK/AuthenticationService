using AutoMapper;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Services;
using Skuzzle.Core.Authentication.Service.Storage.Entities;
using Skuzzle.Core.Lib.MongoDb.Context;
using Skuzzle.Core.Lib.ResultClass;
using System.Linq.Expressions;

namespace Skuzzle.Core.Authentication.Service.Storage;

public class EncryptedRepository<TModel, TEntity> : IRepository<TModel>
    where TModel : class, IModel
    where TEntity : class, IEncryptedEntity
{
    private readonly ILogger<EncryptedRepository<TModel, TEntity>> _logger;
    private readonly IMongoDbContext _context;
    private readonly IEncryptionService _encryptionService;
    private readonly IMapper _mapper;

    public EncryptedRepository(
        ILogger<EncryptedRepository<TModel, TEntity>> logger,
        IMongoDbContext context,
        IEncryptionService encryptionService,
        IMapper mapper)
    {
        _logger = logger;
        _context = context;
        _encryptionService = encryptionService;
        _mapper = mapper;
    }

    public Task<Result<bool>> CountAsync(CancellationToken ct = default) =>
        throw new NotImplementedException();
    

    public async Task<Result> CreateAsync(TModel data, CancellationToken ct = default)
    {
        try
        {
            var entity = _mapper.Map<TEntity>(data);
            entity.CreatedAt = DateTimeOffset.UtcNow;
            entity.EncryptedData = _encryptionService.Encrypt(data);

            await _context.InsertOneAsync(entity);

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
            var entity = await _context.FindAsync<TEntity>(id, ct);
            if (entity is null)
            {
                return Result.Fail<TModel>("Document not found");
            }

            var model = _encryptionService.Decrypt<TModel>(entity.EncryptedData);
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

            var entity = await _context.FirstOrDefaultAsync(mappedExpression, ct);
            if (entity is null)
            {
                return Result.Fail<TModel>("Document not found");
            }

            var model = _encryptionService.Decrypt<TModel>(entity.EncryptedData);
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
