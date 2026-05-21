namespace AuthenticationService.Shared.Constants;

/// <summary>
/// HTTP <c>Authorization</c> header scheme values.
/// </summary>
public static class AuthSchemeConstants
{
    /// <summary>
    /// Bare scheme name. Stamped into the <see cref="Models.Token.Type"/> field of issued tokens.
    /// </summary>
    public const string Bearer = "Bearer";


    /// <summary>
    /// Scheme as it appears in the header (name + trailing space). Strip when parsing the JWT.
    /// </summary>
    public const string BearerPrefix = "Bearer ";
}
