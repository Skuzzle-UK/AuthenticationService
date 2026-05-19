namespace AuthenticationService.Shared.Constants;

/// <summary>
/// Claim-type names used in tokens issued by the AuthenticationService. Use these
/// instead of magic strings when reading claims from <c>User</c> in a consumer service.
/// </summary>
public static class ClaimConstants
{
    /// <summary>
    /// Subject — who the token is about. The user's stable id. Standard JWT claim.
    /// </summary>
    public const string Sub = "sub";

    /// <summary>
    /// Session ID. Identifies the refresh-token family this access token belongs to.
    /// Survives across rotations within a single login session. Standard OIDC claim.
    /// </summary>
    public const string Sid = "sid";

    /// <summary>
    /// Token's unique ID. Standard JWT claim.
    /// </summary>
    public const string Jti = "jti";

    /// <summary>
    /// Expiration time. Standard JWT claim. Token invalid after this.
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
    /// Role membership. Not a JWT-registered claim; this service's convention.
    /// </summary>
    public const string Role = "role";

    /// <summary>
    /// OAuth client identifier. Present on service-identity tokens (client-credentials
    /// grant) — mirrors <see cref="Sub"/> for those tokens. Some tools (Postman, Insomnia)
    /// expect this name explicitly.
    /// </summary>
    public const string ClientId = "client_id";

    /// <summary>
    /// Space-separated list of granted scopes (resource-action style, e.g.
    /// <c>"inventory.read inventory.write"</c>). Present on service-identity tokens.
    /// Consumers parse and check via the <c>AddScopePolicy</c> helper in
    /// <c>AuthenticationService.Client</c>.
    /// </summary>
    public const string Scope = "scope";

    /// <summary>
    /// Authorized party — the party that the token was issued to. For service-identity
    /// tokens this mirrors <see cref="ClientId"/>. Standard OIDC Core §2 claim.
    /// </summary>
    public const string Azp = "azp";
}