namespace AuthenticationService.Constants;

/// <summary>
/// Standard <c>/.well-known/</c> path fragments served by <c>WellKnownController</c>.
/// Names follow RFC 8615 (well-known URIs) and the OpenID Connect Discovery spec —
/// don't change them, consumers expect exact paths.
/// </summary>
public static class WellKnownPaths
{
    /// <summary>
    /// The <c>.well-known</c> URI prefix from RFC 8615.
    /// </summary>
    public const string Prefix = ".well-known";

    /// <summary>
    /// JSON Web Key Set — the public signing keys consumers use to validate JWTs.
    /// </summary>
    public const string Jwks = "jwks.json";

    /// <summary>
    /// OpenID Connect discovery document. Consumers point JwtBearer's <c>Authority</c> at the parent URL and JwtBearer fetches this automatically.
    /// </summary>
    public const string OpenIdConfiguration = "openid-configuration";
}