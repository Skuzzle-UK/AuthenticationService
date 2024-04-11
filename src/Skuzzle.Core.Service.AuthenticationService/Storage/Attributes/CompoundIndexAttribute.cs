namespace Skuzzle.Core.Service.AuthenticationService.Storage.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public class CompoundIndexAttribute : IndexAttribute
{
    /// <summary>
    /// All properties with this attribute and same name property are treated as set and combined into one compound index. 
    /// </summary>
    /// <param name="name">String name of compound index set</param>
    /// <param name="direction">IndexDirection.Ascending or IndexDirection.Descending</param>
    /// <param name="unique">If any member of the index set has unique set to true the compound index will only allow unique values.</param>
    /// <param name="ttl">Automatically removes documents after number of seconds. Negative values disable TTL</param>
    public CompoundIndexAttribute(string name, IndexDirection direction = IndexDirection.ASCENDING, bool unique = false, int ttl = -1)
        : base(direction, unique, ttl)
    {
        IndexName = name;
    }

    public string IndexName { get; private set; } = string.Empty;
}