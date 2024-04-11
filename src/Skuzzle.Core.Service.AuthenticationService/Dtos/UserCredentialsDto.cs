using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Service.AuthenticationService.Dtos;

public class UserCredentialsDto
{
    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;
}
