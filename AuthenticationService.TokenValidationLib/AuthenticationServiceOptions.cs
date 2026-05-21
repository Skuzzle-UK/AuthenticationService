using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.TokenValidationLib;

/// <summary>
/// Settings consumed by <c>AddAuthenticationServiceJwt</c> to validate access tokens.
/// </summary>
public class AuthenticationServiceOptions
{
    /// <summary>
    /// Base URL of the auth service. Used to discover signing keys via
    /// <c>{Authority}/.well-known/openid-configuration</c>.
    /// </summary>
    [Required]
    public string Authority { get; set; } = default!;

    /// <summary>
    /// Expected <c>aud</c> claim (e.g. "platform-api"). Mismatches are rejected.
    /// </summary>
    [Required]
    public string Audience { get; set; } = default!;

    /// <summary>
    /// Expected <c>iss</c> claim. Explicit configuration avoids depending on OIDC
    /// discovery succeeding at validation time.
    /// </summary>
    [Required]
    public string Issuer { get; set; } = default!;

    /// <summary>
    /// Requires HTTPS for the metadata endpoint. Set false in Development if needed.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;
}
