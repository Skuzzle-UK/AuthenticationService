using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Controllers;

/// <summary>
/// Form-encoded request body for <c>POST /oauth/token</c>. Field names match RFC 6749
/// §4.4 (client_credentials grant) — snake_case is the OAuth wire convention.
///
/// <para>Credentials can also be supplied via the <c>Authorization: Basic</c> header
/// (RFC 6749 §2.3.1) instead of in the body; the controller checks the header first
/// and falls back to the body fields. If both are present and disagree, the controller
/// rejects with <c>invalid_request</c>.</para>
///
/// <para>This type lives in the auth project (not in <c>AuthenticationService.Shared</c>)
/// because it's an MVC model-binding artifact — the <c>[FromForm(Name = "...")]</c>
/// attributes pull in <c>Microsoft.AspNetCore.Mvc</c>. Consumers building a form-encoded
/// request body don't need this type; they construct the body directly.</para>
/// </summary>
public class OAuthTokenRequest
{
    /// <summary>Must be <c>"client_credentials"</c>. Any other value yields <c>unsupported_grant_type</c>.</summary>
    [FromForm(Name = "grant_type")]
    public string? GrantType { get; set; }

    /// <summary>The client_id. Optional if supplied via Basic auth header.</summary>
    [FromForm(Name = "client_id")]
    public string? ClientId { get; set; }

    /// <summary>The client_secret. Optional if supplied via Basic auth header.</summary>
    [FromForm(Name = "client_secret")]
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Target audience for the token (e.g. <c>inventory-api</c>). Required. A token is
    /// scoped to a single audience — multi-audience requests must be issued as separate
    /// tokens.
    /// </summary>
    [FromForm(Name = "audience")]
    public string? Audience { get; set; }

    /// <summary>
    /// Space-separated list of scopes (e.g. <c>"inventory.read inventory.write"</c>).
    /// Required. Every requested scope must be present in the client's allow-list
    /// (<c>ClientScopes</c>) for the supplied <see cref="Audience"/> — otherwise
    /// <c>invalid_scope</c>.
    /// </summary>
    [FromForm(Name = "scope")]
    public string? Scope { get; set; }
}
