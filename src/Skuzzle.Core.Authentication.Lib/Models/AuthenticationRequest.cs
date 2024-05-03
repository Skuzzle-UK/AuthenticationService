using Skuzzle.Core.Authentication.Lib.Enums;

namespace Skuzzle.Core.Authentication.Lib.Models;

public class AuthenticationRequest
{
    public GrantType GrantType { get; set; }

    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    public string? Username { get; set; }

    public string? Password { get; set; }

    public string? RefreshToken { get; set; }
}