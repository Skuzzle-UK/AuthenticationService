using System.Text.Json.Serialization;

namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Success response from <c>POST /oauth/token</c>. Wire format per RFC 6749 §5.1 —
/// snake_case field names are part of the OAuth contract; consumers (including the
/// <c>AuthenticationService.TokenClientLib</c> helpers) deserialise against this shape.
/// </summary>
public class OAuthTokenResponse
{
    /// <summary>
    /// The JWT itself. Sent in <c>Authorization: Bearer &lt;value&gt;</c> on subsequent calls.
    /// </summary>
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = default!;

    /// <summary>
    /// Always <c>"Bearer"</c> from this endpoint.
    /// </summary>
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// Lifetime of the token in seconds. Echoes <c>ClientCredentialsSettings.TokenLifetimeInHours</c> ÷ 3600.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    /// <summary>
    /// Space-separated list of scopes the issued token actually carries. Echoes the request's <c>scope</c> param when all scopes were granted.
    /// </summary>
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = default!;
}
