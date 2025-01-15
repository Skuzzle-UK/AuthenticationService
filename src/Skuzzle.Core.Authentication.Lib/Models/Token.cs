using System.Text.Json.Serialization;

namespace Skuzzle.Core.Authentication.Lib.Models;

public class Token
{
    [JsonPropertyName("userId")]
    public Guid UserId { get; private set; }

    [JsonPropertyName("accessToken")]
    public string? AccessToken { get; private set; }

    [JsonPropertyName("expiresAt")]
    public DateTimeOffset? ExpiresAt { get; private set; }

    [JsonPropertyName("refreshToken")]
    public string? RefreshToken { get; private set; }

    [JsonPropertyName("refreshExpiresAt")]
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
