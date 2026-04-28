using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Client;

/// <summary>
/// Settings consumed by <c>AddAuthenticationServiceJwt</c> to validate access tokens
/// issued by the central authentication service.
/// </summary>
public class AuthenticationServiceOptions
{
    /// <summary>
    /// Base URL of the authentication service. JwtBearer uses this to discover the
    /// signing keys via <c>{Authority}/.well-known/openid-configuration</c>.
    /// </summary>
    [Required]
    public string Authority { get; set; } = default!;

    /// <summary>
    /// Expected <c>aud</c> claim. Must match the issuer's configured audience
    /// (e.g. "platform-api"). Tokens with a different audience are rejected.
    /// </summary>
    [Required]
    public string Audience { get; set; } = default!;

    /// <summary>
    /// Expected <c>iss</c> claim. Must match <c>ValidIssuer</c> in the auth service's
    /// JWTSettings (e.g. "https://auth.example.com"). When provided, issuer validation
    /// is explicit and does not depend on OIDC discovery succeeding.
    /// </summary>
    [Required]
    public string Issuer { get; set; } = default!;

    /// <summary>
    /// When true, requires HTTPS for the metadata endpoint. Set to false in
    /// Development if the auth service is reachable only over HTTP.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;
}
