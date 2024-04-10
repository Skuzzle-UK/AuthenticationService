namespace Skuzzle.Core.Service.AuthenticationService.Models;

public class User : IModel
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Username { get; set; } = string.Empty;

    public required byte[] Hash { get; set; }

    public required byte[] Salt { get; set; }

    public required string Email { get; set; }

    public string FirstName { get; set; } = string.Empty;

    public string LastName { get; set; } = string.Empty;

    public string Phone { get; set; } = string.Empty;

    public string Country { get; set; } = string.Empty;

    public List<string> Roles { get; set; } = new List<string>() { "Unconfirmed User" };
}
