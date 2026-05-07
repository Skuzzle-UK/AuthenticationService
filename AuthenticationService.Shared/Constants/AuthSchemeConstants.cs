namespace AuthenticationService.Shared.Constants;

/// <summary>
/// HTTP <c>Authorization</c> header scheme values. Used both when issuing tokens (the
/// <see cref="Bearer"/> scheme is what we tell clients to use) and when parsing them back
/// off incoming requests (strip <see cref="BearerPrefix"/> before treating the rest as
/// the JWT).
/// </summary>
public static class AuthSchemeConstants
{
    /// <summary>
    /// Bare scheme name. Stamped into the <see cref="Models.Token.Type"/> field of issued tokens.
    /// </summary>
    public const string Bearer = "Bearer";


    /// <summary>
    /// The scheme as it appears in the header — name plus the trailing space. Strip this when parsing the JWT out of the <c>Authorization</c> header value.
    /// </summary>
    public const string BearerPrefix = "Bearer ";
}
