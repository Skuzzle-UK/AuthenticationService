using MongoDB.Driver;
using Skuzzle.Core.Service.AuthenticationService.Storage.Attributes;
using System.Reflection;

namespace Skuzzle.Core.Service.AuthenticationService.Extensions;

public static class PropertyInfoExtensions
{
    // TODO: There are other options to indexes including sparse for example that should be handled by these methods and the index related attributes. /nb
    public static IEnumerable<CreateIndexModel<T>> CreateIndexModels<T>(this PropertyInfo[] properties)
    {
        var createIndexModels = new List<CreateIndexModel<T>>();

        foreach (var property in properties)
        {
            object[] attributes = property.GetCustomAttributes(true);

            foreach (IndexAttribute indexAttribute in attributes.Where(o => o.GetType() == typeof(IndexAttribute)))
            {
                var indexKeysDefinition = indexAttribute.Direction switch
                {
                    IndexDirection.DESCENDING => Builders<T>.IndexKeys.Descending(property.Name),
                    _ => Builders<T>.IndexKeys.Ascending(property.Name),
                };

                createIndexModels.Add(
                    new CreateIndexModel<T>(
                        indexKeysDefinition,
                        new CreateIndexOptions()
                        {
                            Name = $"{property.Name}_{indexAttribute.Direction}",
                            Unique = indexAttribute.Unique,
                            ExpireAfter = indexAttribute.Ttl
                        }));
            }
        }
        return createIndexModels;
    }

    public static IEnumerable<CreateIndexModel<T>> CreateCompoundIndexModels<T>(this PropertyInfo[] properties)
    {
        var createIndexModels = new List<CreateIndexModel<T>>();

        var compoundIndexs = new Dictionary<string, CompoundIndexAttribute>();

        foreach (var property in properties)
        {
            object[] attributes = property.GetCustomAttributes(true);

            foreach (CompoundIndexAttribute compoundIndexAttribute in attributes.OfType<CompoundIndexAttribute>())
            {
                compoundIndexs.Add(property.Name, compoundIndexAttribute);
            }
        }

        var distinctCompoundIndexs = compoundIndexs.Values.Select(o => o.IndexName).Distinct().ToList();

        foreach (var index in distinctCompoundIndexs)
        {
            var indexProperties = compoundIndexs.Where(o => o.Value.IndexName == index).Select(o => o.Key);
            var indexKeysDefinitionBuilder = Builders<T>.IndexKeys;
            var indexKeysDefinition = new List<IndexKeysDefinition<T>>();

            var unique = false;
            TimeSpan? ttl = null;
            var indexName = string.Empty;

            foreach (var name in indexProperties)
            {
                indexKeysDefinition.Add(compoundIndexs[name].Direction == IndexDirection.ASCENDING
                    ? indexKeysDefinitionBuilder.Ascending(name)
                    : indexKeysDefinitionBuilder.Descending(name));

                unique = unique || compoundIndexs[name].Unique;

                ttl = compoundIndexs[name].Ttl > (ttl ?? TimeSpan.MinValue)
                    ? compoundIndexs[name].Ttl
                    : ttl;

                if (indexName != string.Empty)
                {
                    indexName += "_";
                }

                indexName += $"{name}_{compoundIndexs[name].Direction}";
            }

            createIndexModels.Add(
                new CreateIndexModel<T>(
                    indexKeysDefinitionBuilder.Combine(indexKeysDefinition),
                    new CreateIndexOptions()
                    {
                        Name = indexName,
                        Unique = unique
                    }));
        }

        return createIndexModels;
    }
}
