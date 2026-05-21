namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Thrown when the outgoing-token client can't obtain a token. <see cref="Error"/>
/// carries the OAuth <c>error</c> code for 4xx config failures (e.g. <c>invalid_client</c>,
/// <c>invalid_scope</c>) or <c>"transient_failure"</c> for 5xx after all retries.
/// </summary>
public class ServiceTokenException : Exception
{
    /// <summary>
    /// OAuth <c>error</c> code, or <c>"transient_failure"</c> for 5xx-shaped errors.
    /// </summary>
    public string Error { get; }

    /// <summary>
    /// OAuth <c>error_description</c> if the server provided one, otherwise null.
    /// </summary>
    public string? ErrorDescription { get; }

    /// <summary>
    /// Creates a <see cref="ServiceTokenException"/> with the given OAuth error code and optional description.
    /// </summary>
    public ServiceTokenException(string error, string? errorDescription, Exception? innerException = null)
        : base(BuildMessage(error, errorDescription), innerException)
    {
        Error = error;
        ErrorDescription = errorDescription;
    }

    private static string BuildMessage(string error, string? description) =>
        description is null ? $"Token request failed: {error}." : $"Token request failed: {error} — {description}.";
}
