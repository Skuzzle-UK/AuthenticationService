namespace Skuzzle.Core.Service.AuthenticationGateway.Storage.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public class IndexAttribute : Attribute
{
    public IndexAttribute(bool unique = false, IndexDirection direction = IndexDirection.ASCENDING)
    {
        Unique = unique;
        Direction = direction;
    }
    public IndexDirection Direction { get; set; }
    public bool Unique { get; set; }
}