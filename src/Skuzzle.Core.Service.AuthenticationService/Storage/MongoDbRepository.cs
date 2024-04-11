using AutoMapper;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using Skuzzle.Core.Service.AuthenticationService.Extensions;
using Skuzzle.Core.Service.AuthenticationService.Models;
using Skuzzle.Core.Service.AuthenticationService.Settings;
using Skuzzle.Core.Service.AuthenticationService.Storage.Entities;
using System.Linq.Expressions;

namespace Skuzzle.Core.Service.AuthenticationService.Storage;

public class MongoDbRepository<TModel, TEntity> : IRepository<TModel>
    where TModel : IModel
    where TEntity : IEntity
{
    private readonly MongoDbSettings _settings;
    private readonly IMapper _mapper;
    private readonly IMongoCollection<TEntity> _collection;

    public MongoDbRepository(
        IOptions<MongoDbSettings> settings,
        IMapper mapper)
    {
        _settings = settings.Value;
        _mapper = mapper;

        var mongoClient = new MongoClient(_settings.ConnectionString);
        var mongoDatabase = mongoClient.GetDatabase(_settings.DatabaseName);
        _collection = mongoDatabase.GetCollection<TEntity>($"{typeof(TModel).Name}s");

        var properties = typeof(TEntity).GetProperties();

        var createIndexModels = properties.CreateIndexModels<TEntity>();
        var createCompoundIndexModels = properties.CreateCompoundIndexModels<TEntity>();

        _collection.Indexes.CreateMany(createIndexModels);
        _collection.Indexes.CreateMany(createCompoundIndexModels);

        var updatedIndexes = _collection.Indexes.List().ToList();

        var createdIndexNames = createIndexModels.Select(index => index.Options.Name).Concat(createCompoundIndexModels.Select(index => index.Options.Name));

        var updatedIndexNames = updatedIndexes.Select(index => index["name"].AsString);

        var obsoleteIndexes = updatedIndexNames.Except(createdIndexNames);
        foreach (var index in obsoleteIndexes)
        {
            if (index != "_id_")
            {
                _collection.Indexes.DropOne(index);
            }
        }

    }

    //TODO: Methods should return result type Ok or Failure etc with data from DB. Needs try catches too /nb
    public async Task InsertAsync(TModel document, CancellationToken ct = default)
    {
        var entity = _mapper.Map<TEntity>(document);
        await _collection.InsertOneAsync(entity, null, ct);
    }

    public async Task<List<TModel>> FindAsync(CancellationToken ct = default)
    {
        var results = await _collection.Find(_ => true).ToListAsync(ct);
        return _mapper.Map<List<TModel>>(results);
    }

    public async Task<TModel?> FindAsync(Guid guid, CancellationToken ct = default)
    {
        var result = await _collection.Find(x => x.Id == guid).FirstOrDefaultAsync(ct);
        return _mapper.Map<TModel>(result);
    }
    public async Task<TModel?> FindAsync(Expression<Func<TModel, bool>> exp, CancellationToken ct = default)
    {
        var mappedExpression = _mapper.Map<Expression<Func<TEntity, bool>>>(exp);
        var result = await _collection.Find(mappedExpression).FirstOrDefaultAsync(ct);
        return _mapper.Map<TModel>(result);
    }
    public async Task<List<TModel>> FindManyAsync(Expression<Func<TModel, bool>> exp, CancellationToken ct = default)
    {
        var mappedExpression = _mapper.Map<Expression<Func<TEntity, bool>>>(exp);
        var result = await _collection.Find(mappedExpression).ToListAsync(ct);
        return _mapper.Map<List<TModel>>(result);
    }

    public async Task DeleteAsync(Guid Guid, CancellationToken ct = default)
    {
        await _collection.DeleteOneAsync(x => x.Id == Guid, ct);
    }

    public async Task UpdateAsync(TModel document, CancellationToken ct = default)
    {
        var entity = _mapper.Map<TEntity>(document);
        await _collection.ReplaceOneAsync(x => x.Id == entity.Id, entity, cancellationToken: ct);
    }

}
