namespace Skuzzle.Core.Service.AuthenticationService.Storage.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public class IndexAttribute : Attribute
{
    /// <summary>
    /// Creates an index on the property
    /// </summary>
    /// <param name="direction">IndexDirection.Ascending or IndexDirection.Descending</param>
    /// <param name="unique">If unique is set to true the index will only allow unique values.</param>
    /// <param name="ttl">Automatically removes documents after nbumber of seconds. Negative values disable TTL</param>
    public IndexAttribute(IndexDirection direction = IndexDirection.ASCENDING, bool unique = false, int ttl = -1)
    {
        Unique = unique;
        Direction = direction;
        if (ttl > 0)
        Ttl = TimeSpan.FromSeconds(ttl);
    }

    public IndexDirection Direction { get; private set; }
    
    public bool Unique { get; private set; }

    public TimeSpan? Ttl { get; private set;}
}