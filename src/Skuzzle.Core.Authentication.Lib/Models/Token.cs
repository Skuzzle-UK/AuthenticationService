namespace Skuzzle.Core.Authentication.Lib.Models;

public class Token
{
    public Guid UserId { get; set; }

    public string AccessToken { get; private set; }

    public DateTimeOffset? ExpiresAt { get; private set; }

    public string? RefreshToken { get; private set; }

    public DateTimeOffset? RefreshExpiresAt { get; private set; }

    public Token(Guid userId, string accessToken, DateTimeOffset? expiresAt = null, string? refreshToken = null, DateTimeOffset? refreshExpiresAt = null)
    {
        UserId = userId;
        AccessToken = accessToken;
        ExpiresAt = expiresAt;
        RefreshToken = refreshToken;
        RefreshExpiresAt = refreshExpiresAt;
    }
}
