namespace AuthenticationService.Shared.Models;

public class Token
{
    public string? Value { get; set; }
    public DateTime? Expires { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiresAt { get; set; }
    public string? Type { get; set; }

    public Token(string type, string value)
    {
        Type = type;
        Value = value;
    }

    public Token(string type, string value, DateTime? expires)
    {
        Type = type;
        Value = value;
        Expires = expires;
    }

    public Token(string type, string value, DateTime? expires, string refreshToken)
    {
        Type = type;
        Value = value;
        Expires = expires;
        RefreshToken = refreshToken;
    }

    public Token(string type, string value, DateTime? expires, string refreshToken, DateTime refreshTokenExpiresAt)
    {
        Type = type;
        Value = value;
        Expires = expires;
        RefreshToken = refreshToken;
        RefreshTokenExpiresAt = refreshTokenExpiresAt;
    }
}
