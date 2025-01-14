namespace Skuzzle.Core.Authentication.Lib.Models;

public class Role : IModel
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public required string Name { get; set; } = string.Empty;
}
