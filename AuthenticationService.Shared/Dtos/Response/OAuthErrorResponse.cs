using System.Text.Json.Serialization;

namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// RFC 6749 §5.2 error envelope from <c>POST /oauth/token</c>. <c>error_description</c>
/// is deliberately bland — no leakage about whether a client id exists.
/// </summary>
public class OAuthErrorResponse
{
    /// <summary>
    /// Standard RFC 6749 error code: <c>invalid_request</c>, <c>invalid_client</c>,
    /// <c>invalid_grant</c>, <c>unauthorized_client</c>, <c>unsupported_grant_type</c>, or <c>invalid_scope</c>.
    /// </summary>
    [JsonPropertyName("error")]
    public string Error { get; set; } = default!;

    /// <summary>
    /// Human-readable description. Optional per RFC; populated for every error path this server emits.
    /// </summary>
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
}
