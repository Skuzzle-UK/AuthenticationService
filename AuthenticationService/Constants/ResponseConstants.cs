namespace AuthenticationService.Constants;

/// <summary>
/// Keys used to label entries in the <c>Errors</c> dictionary on API responses.
/// Pairs the API error with a short, stable category so consumers can branch on the
/// response without parsing the message text.
/// </summary>
public static class ResponseConstants
{
    /// <summary>
    /// The request was malformed or failed validation. Maps to HTTP 400.
    /// </summary>
    public const string BadRequest = "Bad Request";

    /// <summary>
    /// The caller isn't authenticated, or their token is no longer valid. Maps to HTTP 401.
    /// </summary>
    public const string Unauthorized = "Unauthorized";
}