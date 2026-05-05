namespace AuthenticationService.Shared.Constants;

/// <summary>
/// Claim-type names used in tokens issued by the AuthenticationService. Use these
/// instead of magic strings when reading claims from <c>User</c> in a consumer service.
/// </summary>
public static class ClaimConstants
{
    /// <summary>
    /// Subject. Whoe the token is about. Stable user ID. Standard JWT claim.
    /// </summary>
    public const string Sub = "sub";

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
}