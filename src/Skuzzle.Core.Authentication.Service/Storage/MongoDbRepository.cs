﻿using AutoMapper;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Extensions;
using Skuzzle.Core.Authentication.Service.Services;
using Skuzzle.Core.Authentication.Service.Settings;
using Skuzzle.Core.Authentication.Service.Storage.Attributes;
using Skuzzle.Core.Authentication.Service.Storage.Entities;
using Skuzzle.Core.Lib.ResultClass;
using System.Linq.Expressions;
using System.Reflection;

namespace Skuzzle.Core.Authentication.Service.Storage;

public class MongoDbRepository<TModel, TEntity> : IRepository<TModel>
    where TModel : IModel
    where TEntity : IEntity
{
    private readonly ILogger<MongoDbRepository<TModel, TEntity>> _logger;
    private readonly MongoDbSettings _settings;
    private readonly IMapper _mapper;
    private readonly IEncryptionService _encryptionService;
    private readonly IMongoCollection<TEntity> _collection;

    // TODO: Finish adding encryption capabilities /nb
    public MongoDbRepository(
        ILogger<MongoDbRepository<TModel, TEntity>> logger,
        IOptions<MongoDbSettings> settings,
        IMapper mapper,
        IEncryptionService encryptionService)
    {
        _logger = logger;
        _settings = settings.Value;
        _mapper = mapper;
        _encryptionService = encryptionService;

        // TODO: Look at moving this out to application startup as it should probably fail at start rather than when first used /nb
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

    public async Task<Result> InsertAsync(TModel document, CancellationToken ct = default)
    {
        try
        {
            var entity = _mapper.Map<TEntity>(document);

            var properties = typeof(TEntity).GetProperties()
                    .Where(p => p.GetCustomAttribute<EncryptAttribute>() != null);

            foreach (var property in properties)
            {
                property.SetValue(entity, _encryptionService.Encrypt(property.GetValue(entity)));
            }

            await _collection.InsertOneAsync(entity, null, ct);
            return Result.Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "MongoDb InsertAsync failed with error: {ErrorMessage}", ex.Message);
            return Result.Fail(ex, "MongoDb InsertAsync failed with error: {ErrorMessage}", ex.Message);
        }
    }

    public async Task<Result<List<TModel>>> FindAsync(CancellationToken ct = default)
    {
        try
        {
            var results = await _collection.Find(_ => true).ToListAsync(ct);
            return Result.Ok(_mapper.Map<List<TModel>>(results));
        }
        catch(Exception ex)
        {
            _logger.LogError(ex, "MongoDb FindAsync failed with error: {ErrorMessage}", ex.Message);
            return Result.Fail<List<TModel>>(ex, "MongoDb FindAsync failed with error: {ErrorMessage}", ex.Message);
        }
    }

    public async Task<Result<TModel>> FindAsync(Guid guid, CancellationToken ct = default)
    {
        try
        {
            var result = await _collection.Find(x => x.Id == guid).FirstOrDefaultAsync(ct);

            var properties = typeof(TEntity).GetProperties()
                .Where(p => p.GetCustomAttribute<EncryptAttribute>() != null);

            foreach (var property in properties)
            {
                property.SetValue(result, _encryptionService.Encrypt(property.GetValue(result)));
            }

            return Result.Ok(_mapper.Map<TModel>(result));
        }
        catch(Exception ex)
        {
            _logger.LogError(ex, "MongoDb FindAsync failed with error: {ErrorMessage}", ex.Message);
            return Result.Fail<TModel>(ex, "MongoDb FindAsync failed with error: {ErrorMessage}", ex.Message);
        }
    }

    public async Task<Result<TModel>> FindAsync(Expression<Func<TModel, bool>> exp, CancellationToken ct = default)
    {
        try
        {
            var mappedExpression = _mapper.Map<Expression<Func<TEntity, bool>>>(exp);
            var result = await _collection.Find(mappedExpression).FirstOrDefaultAsync(ct);
            return Result.Ok(_mapper.Map<TModel>(result));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "MongoDb FindAsync failed with error: {ErrorMessage}", ex.Message);
            return Result.Fail<TModel>(ex, "MongoDb FindAsync failed with error: {ErrorMessage}", ex.Message);
        }
    }

    public async Task<Result<List<TModel>>> FindManyAsync(Expression<Func<TModel, bool>> exp, CancellationToken ct = default)
    {
        try
        {
            var mappedExpression = _mapper.Map<Expression<Func<TEntity, bool>>>(exp);
            var result = await _collection.Find(mappedExpression).ToListAsync(ct);
            return Result.Ok(_mapper.Map<List<TModel>>(result));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "MongoDb FindManyAsync failed with error: {ErrorMessage}", ex.Message);
            return Result.Fail<List<TModel>>(ex, "MongoDb FindManyAsync failed with error: {ErrorMessage}", ex.Message);
        }
    }

    public async Task<Result> DeleteAsync(Guid Guid, CancellationToken ct = default)
    {
        try
        {
            await _collection.DeleteOneAsync(x => x.Id == Guid, ct);
            return Result.Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "MongoDb DeleteAsync failed with error: {ErrorMessage}", ex.Message);
            return Result.Fail<TModel>(ex, "MongoDb DeleteAsync failed with error: {ErrorMessage}", ex.Message);
        }
    }

    public async Task<Result> UpdateAsync(TModel document, CancellationToken ct = default)
    {
        try
        {
            var entity = _mapper.Map<TEntity>(document);
            await _collection.ReplaceOneAsync(x => x.Id == entity.Id, entity, cancellationToken: ct);
            return Result.Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "MongoDb FindAsync failed with error: {ErrorMessage}", ex.Message);
            return Result.Fail<TModel>(ex, "MongoDb FindAsync failed with error: {ErrorMessage}", ex.Message);
        }
    }

}