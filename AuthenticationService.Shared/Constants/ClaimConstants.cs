namespace AuthenticationService.Shared.Constants;

/// <summary>
/// Claim-type names used in tokens issued by the AuthenticationService.
/// </summary>
public static class ClaimConstants
{
    /// <summary>
    /// Subject — the user's stable id. Standard JWT claim.
    /// </summary>
    public const string Sub = "sub";

    /// <summary>
    /// Session ID — the refresh-token family this access token belongs to. Standard OIDC claim.
    /// </summary>
    public const string Sid = "sid";

    /// <summary>
    /// Token's unique ID. Standard JWT claim.
    /// </summary>
    public const string Jti = "jti";

    /// <summary>
    /// Expiration time. Standard JWT claim.
    /// </summary>
    public const string Exp = "exp";

    /// <summary>
    /// Username (display).
    /// </summary>
    public const string Name = "name";

    /// <summary>
    /// Email address.
    /// </summary>
    public const string Email = "email";

    /// <summary>
    /// Role membership. Not JWT-registered; this service's convention.
    /// </summary>
    public const string Role = "role";

    /// <summary>
    /// OAuth client identifier. Present on service-identity tokens; mirrors <see cref="Sub"/> for those.
    /// </summary>
    public const string ClientId = "client_id";

    /// <summary>
    /// Space-separated list of granted scopes (e.g. <c>"inventory.read inventory.write"</c>).
    /// Present on service-identity tokens.
    /// </summary>
    public const string Scope = "scope";

    /// <summary>
    /// Authorized party — mirrors <see cref="ClientId"/> on service-identity tokens. Standard OIDC Core §2 claim.
    /// </summary>
    public const string Azp = "azp";
}