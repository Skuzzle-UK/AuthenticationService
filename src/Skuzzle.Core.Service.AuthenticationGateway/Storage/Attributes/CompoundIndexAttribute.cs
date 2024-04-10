namespace Skuzzle.Core.Service.AuthenticationGateway.Storage.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public class CompoundIndexAttribute : Attribute
{
    public CompoundIndexAttribute(string indexName, bool unique = false, IndexDirection direction = IndexDirection.ASCENDING)
    {
        IndexName = indexName;
        Unique = unique;
        Direction = direction;
    }
    public string IndexName { get; set; } = string.Empty;
    public bool Unique { get; set; }
    public IndexDirection Direction { get; set; }
}