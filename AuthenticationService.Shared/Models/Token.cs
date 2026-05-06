namespace AuthenticationService.Shared.Models;

/// <summary>
/// The access + refresh token pair returned to the client after a successful login or
/// refresh. <see cref="Value"/> goes in the <c>Authorization</c> header on subsequent
/// requests; <see cref="RefreshToken"/> is sent back to <c>/refresh</c> to swap the pair
/// for a new one once the access token expires.
/// </summary>
public class Token
{
    /// <summary>The access token (the JWT itself).</summary>
    public string? Value { get; set; }

    /// <summary>When the access token expires.</summary>
    public DateTime? Expires { get; set; }

    /// <summary>The refresh token (an opaque random string — keep it secret).</summary>
    public string? RefreshToken { get; set; }

    /// <summary>When the refresh token expires.</summary>
    public DateTime? RefreshTokenExpiresAt { get; set; }

    /// <summary>Token scheme — currently always <c>"Bearer"</c>.</summary>
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

    public Token(string type, string value, DateTime? expires, string refreshToken, DateTime? refreshTokenExpiresAt)
    {
        Type = type;
        Value = value;
        Expires = expires;
        RefreshToken = refreshToken;
        RefreshTokenExpiresAt = refreshTokenExpiresAt;
    }
}
