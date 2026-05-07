namespace AuthenticationService.Constants;

/// <summary>
/// Query-string parameter names used in URLs the auth service generates and consumes
/// (email-link tokens, callback URIs, redirects). Centralised so producer and consumer
/// stay in sync — change the name here and both sides update.
/// </summary>
public class UriConstants
{
    /// <summary>
    /// The single-use token from an email link (password reset, email confirm, etc.).
    /// </summary>
    public const string Token = "token";

    /// <summary>
    /// The user's email address — paired with <see cref="Token"/> so the server can look up the user.
    /// </summary>
    public const string Email = "email";

    /// <summary>
    /// Marker indicating the link came from a lockout-flow email rather than a regular reset.
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
    /// The URL the user should be redirected to after a flow completes (e.g. landing on the consumer's UI after email confirmation).
    /// </summary>
    public const string CallBackUri = "callbackUri";
}