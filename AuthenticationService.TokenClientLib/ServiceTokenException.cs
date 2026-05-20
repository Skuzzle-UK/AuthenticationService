namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Thrown when the outgoing-token client can't obtain a token. Two flavours:
///
/// <list type="bullet">
///   <item><description><b>Config-shaped failures</b> (4xx from <c>/oauth/token</c>) — the
///   call is wrong: bad credentials, unauthorised scope, malformed request. The
///   OAuth <c>error</c> code (<c>invalid_client</c>, <c>invalid_scope</c>, ...) is
///   surfaced in <see cref="Error"/>. Retrying won't help; fix the config.</description></item>
///   <item><description><b>Transient failures</b> (5xx / network) — already retried
///   <c>MaxRetriesOnTransient</c> times before throwing. <see cref="Error"/> is
///   <c>"transient_failure"</c>. The inner exception (if any) carries the last
///   underlying error.</description></item>
/// </list>
///
/// <para>Consumers can catch this generally, or check <see cref="Error"/> to branch on
/// the OAuth code.</para>
/// </summary>
public class ServiceTokenException : Exception
{
    /// <summary>The OAuth <c>error</c> code, or <c>"transient_failure"</c> for 5xx-shaped errors.</summary>
    public string Error { get; }

    /// <summary>The OAuth <c>error_description</c> if the server provided one, otherwise null.</summary>
    public string? ErrorDescription { get; }

    public ServiceTokenException(string error, string? errorDescription, Exception? innerException = null)
        : base(BuildMessage(error, errorDescription), innerException)
    {
        Error = error;
        ErrorDescription = errorDescription;
    }

    private static string BuildMessage(string error, string? description) =>
        description is null ? $"Token request failed: {error}." : $"Token request failed: {error} — {description}.";
}
