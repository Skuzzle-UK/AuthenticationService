namespace Skuzzle.Core.Authentication.Service.Storage.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public class EncryptAttribute : Attribute
{
    /// <summary>
    /// Suggests that property should be encrypted
    /// </summary>
    public EncryptAttribute()
    {
        Encrypt = true;
    }

    public bool Encrypt { get; private set; }
}