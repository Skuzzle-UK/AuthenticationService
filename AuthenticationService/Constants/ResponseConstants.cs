namespace AuthenticationService.Constants;

/// <summary>
/// Stable category keys for the <c>Errors</c> dictionary on API responses — consumers
/// branch on these without parsing message text.
/// </summary>
public static class ResponseConstants
{
    /// <summary>
    /// HTTP 400.
    /// </summary>
    public const string BadRequest = "Bad Request";

    /// <summary>
    /// HTTP 401.
    /// </summary>
    public const string Unauthorized = "Unauthorized";
}