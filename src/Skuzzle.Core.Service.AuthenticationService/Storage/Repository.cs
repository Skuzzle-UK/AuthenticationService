using AutoMapper;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using Skuzzle.Core.Service.AuthenticationService.Models;
using Skuzzle.Core.Service.AuthenticationService.Settings;
using Skuzzle.Core.Service.AuthenticationService.Storage.Attributes;
using Skuzzle.Core.Service.AuthenticationService.Storage.Entities;
using System.Linq.Expressions;

namespace Skuzzle.Core.Service.AuthenticationService.Storage;

public class Repository<TModel, TEntity> : IRepository<TModel>
    where TModel : IModel
    where TEntity : IEntity
{
    private readonly MongoDbSettings _settings;
    private readonly IMapper _mapper;
    private readonly IMongoCollection<TEntity> _collection;

    public Repository(
        IOptions<MongoDbSettings> settings,
        IMapper mapper)
    {
        _settings = settings.Value;
        _mapper = mapper;

        var mongoClient = new MongoClient(_settings.ConnectionString);

        var mongoDatabase = mongoClient.GetDatabase(_settings.DatabaseName);

        _collection = mongoDatabase.GetCollection<TEntity>($"{typeof(TModel).Name}s");

        var compoundIndexFields = new Dictionary<string, string>();
        var compoundIndexDirections = new Dictionary<string, int>();

        var properties = typeof(TEntity).GetProperties();

        foreach (var property in properties)
        {
            object[] attributes = property.GetCustomAttributes(true);
            foreach (object attribute in attributes)
            {
                var indexAttribute = attribute as IndexAttribute;
                if (indexAttribute is not null)
                {
                    IndexKeysDefinition<TEntity>? indexKeysDefinition = indexAttribute.Direction switch
                    {
                        IndexDirection.DESCENDING => Builders<TEntity>.IndexKeys.Descending(property.Name),
                        _ => Builders<TEntity>.IndexKeys.Ascending(property.Name),
                    };

                    var indexModel = new CreateIndexModel<TEntity>(
                        indexKeysDefinition,
                        new CreateIndexOptions()
                        {
                            Unique = indexAttribute.Unique
                        });


                    _collection.Indexes.CreateOne(indexModel);
                }

                var compoundIndexAttribute = attribute as CompoundIndexAttribute;
                if (compoundIndexAttribute is not null)
                {
                    compoundIndexFields.Add(property.Name, compoundIndexAttribute.IndexName);
                    compoundIndexDirections.Add(property.Name, (int)compoundIndexAttribute.Direction);
                }
            }
        }

        var distinctCompoundIndexs = compoundIndexFields.Values.Distinct().ToList();

        foreach (var index in distinctCompoundIndexs)
        {
            // TODO: Add Unique property to compound index somehow /nb
            var indexProperties = compoundIndexFields.Where(o => o.Value == index).Select(o => o.Key);
            var indexBson = new BsonDocument();
            foreach (var name in indexProperties)
            {
                var direction = compoundIndexDirections[name];
                var bsonElement = new BsonElement(name, direction);
                indexBson.Add(bsonElement);
            }

            //TODO: Work out why this is obsolete and how to update it /nb
            _collection.Indexes.CreateOneAsync(indexBson);
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
