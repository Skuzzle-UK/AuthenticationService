namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Resolves OAuth client-credentials tokens for outgoing service-to-service calls.
/// Per-process singleton; caches by <c>(audience, scopes)</c>; refreshes proactively
/// near expiry; deduplicates concurrent refreshes so a thundering herd at expiry hits
/// <c>/oauth/token</c> exactly once.
/// </summary>
public interface IServiceTokenProvider
{
    /// <summary>
    /// Returns a valid service-identity JWT for the given audience + scopes. Hits the
    /// cache when possible; falls through to <c>/oauth/token</c> on miss.
    /// <c>scopes</c> is order-independent — the cache key sorts before comparing.
    /// </summary>
    /// <exception cref="ServiceTokenException">
    /// 4xx config-shaped failure (no retry) or 5xx transient failure after
    /// <c>MaxRetriesOnTransient</c> attempts.
    /// </exception>
    Task<string> GetTokenAsync(string audience, IReadOnlyList<string> scopes, CancellationToken ct = default);

    /// <summary>
    /// Discards any cached token for <c>(audience, scopes)</c>. Called by
    /// <c>ServiceTokenHandler</c> on a downstream 401 with
    /// <c>WWW-Authenticate: Bearer error="invalid_token"</c> to recover from key rotation
    /// or soft-revoke.
    /// </summary>
    void Invalidate(string audience, IReadOnlyList<string> scopes);
}
