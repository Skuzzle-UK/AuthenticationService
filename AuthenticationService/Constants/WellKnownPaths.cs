namespace AuthenticationService.Constants;

/// <summary>
/// <c>/.well-known/</c> path fragments per RFC 8615 / OIDC Discovery. Don't change —
/// consumers expect exact paths.
/// </summary>
public static class WellKnownPaths
{
    /// <summary>
    /// The <c>.well-known</c> URI prefix from RFC 8615.
    /// </summary>
    public const string Prefix = ".well-known";

    /// <summary>
    /// JSON Web Key Set — public signing keys.
    /// </summary>
    public const string Jwks = "jwks.json";

    /// <summary>
    /// OIDC discovery document — JwtBearer fetches this from <c>Authority</c>.
    /// </summary>
    public const string OpenIdConfiguration = "openid-configuration";
}