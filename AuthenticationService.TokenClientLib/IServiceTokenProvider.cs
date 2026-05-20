namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Resolves OAuth client-credentials tokens for outgoing service-to-service calls.
/// Per-process singleton; caches tokens by <c>(audience, scopes)</c> tuple; refreshes
/// proactively at ~80% of the token's lifetime; deduplicates concurrent refresh
/// attempts so a thundering herd at expiry hits <c>/oauth/token</c> exactly once.
///
/// <para>The typical caller is <c>ServiceTokenHandler</c>, registered automatically
/// against an <c>HttpClient</c> via <c>AddServiceToken("aud", scopes)</c>. Direct
/// injection is also fine for non-HttpClient scenarios (gRPC, SignalR, etc.).</para>
/// </summary>
public interface IServiceTokenProvider
{
    /// <summary>
    /// Returns a valid service-identity JWT for the given audience + scopes. Hits the
    /// cache when possible; falls through to <c>/oauth/token</c> on miss.
    /// </summary>
    /// <param name="audience">Per-service audience (e.g. <c>inventory-api</c>). The token will carry this in its <c>aud</c> claim.</param>
    /// <param name="scopes">List of scopes to request. Order-independent — the cache key sorts before comparing.</param>
    /// <param name="ct">Cancellation propagated to the HTTP call(s) used to fetch a new token.</param>
    /// <exception cref="ServiceTokenException">
    /// Thrown on either a 4xx config-shaped failure (immediately, no retry) or a 5xx
    /// transient failure after <c>MaxRetriesOnTransient</c> attempts.
    /// </exception>
    Task<string> GetTokenAsync(string audience, IReadOnlyList<string> scopes, CancellationToken ct = default);

    /// <summary>
    /// Discards any cached token for the given <c>(audience, scopes)</c> tuple. The
    /// next <see cref="GetTokenAsync"/> call refetches.
    ///
    /// <para>Called by <c>ServiceTokenHandler</c> when a downstream returns 401 with
    /// <c>WWW-Authenticate: Bearer error="invalid_token"</c> — signal that the cached
    /// token has gone stale (key rotation, soft-revoke, etc.) and a fresh one should
    /// be obtained.</para>
    /// </summary>
    void Invalidate(string audience, IReadOnlyList<string> scopes);
}
