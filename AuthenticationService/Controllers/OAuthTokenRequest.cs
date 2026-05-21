using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Controllers;

/// <summary>
/// Form-encoded request body for <c>POST /oauth/token</c> (RFC 6749 §4.4). Credentials may also be supplied via Basic auth header; if both are present and disagree the controller rejects with <c>invalid_request</c>.
/// </summary>
public class OAuthTokenRequest
{
    /// <summary>
    /// Must be <c>"client_credentials"</c>.
    /// </summary>
    [FromForm(Name = "grant_type")]
    public string? GrantType { get; set; }

    /// <summary>
    /// The client_id. Optional if supplied via Basic auth header.
    /// </summary>
    [FromForm(Name = "client_id")]
    public string? ClientId { get; set; }

    /// <summary>
    /// The client_secret. Optional if supplied via Basic auth header.
    /// </summary>
    [FromForm(Name = "client_secret")]
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Target audience for the token (e.g. <c>inventory-api</c>). Required. A token is scoped to a single audience.
    /// </summary>
    [FromForm(Name = "audience")]
    public string? Audience { get; set; }

    /// <summary>
    /// Space-separated list of scopes. Required. Every scope must be in the client's allow-list for <see cref="Audience"/> or the request fails with <c>invalid_scope</c>.
    /// </summary>
    [FromForm(Name = "scope")]
    public string? Scope { get; set; }
}
