namespace Skuzzle.Core.Service.AuthenticationGateway.Dtos;

public class UserDto
{
    public required string Username { get; set; }

    public required string Password { get; set; }

    public required string Email { get; set; }

    public string FirstName { get; set; } = string.Empty;

    public string LastName { get; set; } = string.Empty;

    public string Phone { get; set; } = string.Empty;

    public string Country { get; set; } = string.Empty;
}
