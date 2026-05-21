namespace AuthenticationService.Constants;

/// <summary>
/// Query-string parameter names in auth-service URLs (email tokens, callbacks).
/// Centralised so producer and consumer stay in sync.
/// </summary>
public class UriConstants
{
    /// <summary>
    /// Single-use token from an email link.
    /// </summary>
    public const string Token = "token";

    /// <summary>
    /// The user's email address — paired with <see cref="Token"/> so the server can look up the user.
    /// </summary>
    public const string Email = "email";

    /// <summary>
    /// Marker for lockout-flow links vs regular reset links.
    /// </summary>
    public const string Lockout = "lockout";

    /// <summary>
    /// Literal string <c>"true"</c>. Used as the value of <see cref="Lockout"/> when set.
    /// </summary>
    public const string True = "true";

    /// <summary>
    /// Literal string <c>"false"</c>.
    /// </summary>
    public const string False = "false";

    /// <summary>
    /// Post-flow redirect URL (e.g. back to the consumer's UI).
    /// </summary>
    public const string CallBackUri = "callbackUri";
}