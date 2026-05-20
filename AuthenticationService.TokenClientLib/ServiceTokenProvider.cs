using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using AuthenticationService.Shared.Dtos.Response;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthenticationService.TokenClientLib;

/// <inheritdoc />
public class ServiceTokenProvider : IServiceTokenProvider
{
    /// <summary>
    /// Suffix for the discovery doc URL — RFC 8414 §3.
    /// </summary>
    private const string DiscoveryDocPath = "/.well-known/openid-configuration";

    /// <summary>
    /// Name of the <see cref="HttpClient"/> the provider pulls from
    /// <see cref="IHttpClientFactory"/>. Registered by
    /// <c>AddAuthenticationServiceTokenClient</c>.
    /// </summary>
    public const string HttpClientName = "AuthenticationService.ServiceTokenProvider";

    private readonly IHttpClientFactory _httpFactory;
    private readonly ServiceTokenClientOptions _options;
    private readonly ILogger<ServiceTokenProvider> _logger;

    // ─── Cache ───────────────────────────────────────────────────────────────────────
    // Per-key SemaphoreSlim guards concurrent refresh. Two callers seeing an expired
    // token at the same moment converge on a single token fetch via the semaphore.
    private readonly ConcurrentDictionary<CacheKey, CachedToken> _cache = new();
    private readonly ConcurrentDictionary<CacheKey, SemaphoreSlim> _refreshLocks = new();

    // ─── Discovery ───────────────────────────────────────────────────────────────────
    // token_endpoint is resolved once (or via override) and held for the process lifetime.
    // A 404 on the cached endpoint would invalidate it, but in practice the URL is stable
    // for the lifetime of a deploy.
    private string? _resolvedTokenEndpoint;
    private readonly SemaphoreSlim _discoveryLock = new(1, 1);

    public ServiceTokenProvider(
        IHttpClientFactory httpFactory,
        IOptions<ServiceTokenClientOptions> options,
        ILogger<ServiceTokenProvider> logger)
    {
        _httpFactory = httpFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<string> GetTokenAsync(string audience, IReadOnlyList<string> scopes, CancellationToken ct = default)
    {
        var key = MakeKey(audience, scopes);

        // Fast path: cache hit + not yet at the refresh threshold.
        if (_cache.TryGetValue(key, out var cached))
        {
            if (cached.IsValid())
            {
                if (cached.ShouldProactivelyRefresh(_options.RefreshAtFractionOfLifetime))
                {
                    // Fire-and-forget background refresh. Failures here are logged
                    // (via the inner RefreshAsync) and silently dropped — the still-
                    // valid cached token serves the current request fine; we'll retry
                    // the proactive refresh on the next call.
                    _ = Task.Run(() => RefreshAsync(key, audience, scopes, CancellationToken.None));
                }
                return cached.Value;
            }
        }

        // Slow path: cache miss or token expired. Block on refresh.
        return await RefreshAsync(key, audience, scopes, ct);
    }

    public void Invalidate(string audience, IReadOnlyList<string> scopes)
    {
        var key = MakeKey(audience, scopes);
        _cache.TryRemove(key, out _);
    }

    /// <summary>
    /// Fetches a fresh token + populates the cache. Uses a per-key semaphore so
    /// concurrent callers converge on a single <c>/oauth/token</c> hit.
    /// </summary>
    private async Task<string> RefreshAsync(CacheKey key, string audience, IReadOnlyList<string> scopes, CancellationToken ct)
    {
        var semaphore = _refreshLocks.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(ct);
        try
        {
            // Re-check cache after acquiring the lock — another caller may have
            // refreshed it while we were waiting. If they did, just use what they got.
            if (_cache.TryGetValue(key, out var cached) && cached.IsValid()
                && !cached.ShouldProactivelyRefresh(_options.RefreshAtFractionOfLifetime))
            {
                return cached.Value;
            }

            var response = await FetchTokenWithRetriesAsync(audience, scopes, ct);
            var expiresAt = DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn);
            var newToken = new CachedToken(response.AccessToken, expiresAt, response.ExpiresIn);
            _cache[key] = newToken;

            _logger.LogDebug(
                "Service token refreshed for audience={Audience} scopes={Scopes}, expires in {ExpiresIn}s",
                audience, key.NormalisedScopes, response.ExpiresIn);
            return newToken.Value;
        }
        finally
        {
            semaphore.Release();
        }
    }

    /// <summary>
    /// One token-request call, with exponential backoff on 5xx / network errors.
    /// 4xx responses throw immediately — they indicate config / credential errors that
    /// retrying can't fix.
    /// </summary>
    private async Task<OAuthTokenResponse> FetchTokenWithRetriesAsync(string audience, IReadOnlyList<string> scopes, CancellationToken ct)
    {
        var endpoint = await ResolveTokenEndpointAsync(ct);
        var attempt = 0;
        Exception? lastTransient = null;

        while (attempt <= _options.MaxRetriesOnTransient)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                using var http = _httpFactory.CreateClient(HttpClientName);
                using var request = BuildTokenRequest(endpoint, audience, scopes);
                using var response = await http.SendAsync(request, ct);

                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadFromJsonAsync<OAuthTokenResponse>(cancellationToken: ct);
                    if (body is null || string.IsNullOrEmpty(body.AccessToken))
                    {
                        throw new ServiceTokenException(
                            "invalid_response",
                            "Token endpoint returned success but no access_token.");
                    }
                    return body;
                }

                // 4xx — config problem; bubble up immediately.
                if ((int)response.StatusCode is >= 400 and < 500)
                {
                    var error = await TryReadErrorAsync(response, ct);
                    throw new ServiceTokenException(
                        error?.Error ?? "invalid_request",
                        error?.ErrorDescription);
                }

                // 5xx — retry. Record and fall through to the backoff.
                lastTransient = new ServiceTokenException(
                    "transient_failure",
                    $"Token endpoint returned {(int)response.StatusCode}.");
            }
            catch (HttpRequestException ex)
            {
                // Network-level failure — same retry contract as 5xx.
                lastTransient = ex;
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                // HttpClient timeout (request timed out internally), not external cancel.
                lastTransient = new ServiceTokenException("transient_failure", "Token endpoint timed out.");
            }

            attempt++;
            if (attempt > _options.MaxRetriesOnTransient)
            {
                break;
            }

            // Exponential backoff: 250ms, 500ms, 1s, 2s, ... capped at 30s.
            var delay = TimeSpan.FromMilliseconds(Math.Min(30_000, 250 * Math.Pow(2, attempt - 1)));
            _logger.LogWarning(
                "Token endpoint transient failure (attempt {Attempt}/{Max}); retrying in {DelayMs}ms",
                attempt, _options.MaxRetriesOnTransient, delay.TotalMilliseconds);
            await Task.Delay(delay, ct);
        }

        throw new ServiceTokenException(
            "transient_failure",
            $"Token endpoint failed after {_options.MaxRetriesOnTransient + 1} attempts.",
            lastTransient);
    }

    private HttpRequestMessage BuildTokenRequest(string endpoint, string audience, IReadOnlyList<string> scopes)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, endpoint);

        // Credentials via Basic auth (RFC 6749 §2.3.1). Encodes client_id + secret in
        // the header so the body carries only the grant params.
        var basic = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{_options.ClientId}:{_options.ClientSecret}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);

        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["audience"] = audience,
            ["scope"] = string.Join(' ', scopes),
        });

        return request;
    }

    private async Task<OAuthErrorResponse?> TryReadErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<OAuthErrorResponse>(cancellationToken: ct);
        }
        catch
        {
            // Non-JSON or unreadable body — return null, caller falls back to a generic
            // error code. The HTTP status alone is enough to know what's happening.
            return null;
        }
    }

    /// <summary>
    /// Resolves the OAuth token endpoint via either the configured override or OIDC
    /// discovery. Result is cached for the process lifetime — the URL is stable across
    /// a deploy.
    /// </summary>
    private async Task<string> ResolveTokenEndpointAsync(CancellationToken ct)
    {
        if (_resolvedTokenEndpoint is not null)
        {
            return _resolvedTokenEndpoint;
        }

        if (!string.IsNullOrWhiteSpace(_options.TokenEndpointOverride))
        {
            _resolvedTokenEndpoint = _options.TokenEndpointOverride;
            return _resolvedTokenEndpoint;
        }

        await _discoveryLock.WaitAsync(ct);
        try
        {
            if (_resolvedTokenEndpoint is not null)
            {
                return _resolvedTokenEndpoint;
            }

            var discoveryUrl = $"{_options.Authority!.TrimEnd('/')}{DiscoveryDocPath}";
            using var http = _httpFactory.CreateClient(HttpClientName);
            using var response = await http.GetAsync(discoveryUrl, ct);
            response.EnsureSuccessStatusCode();

            var doc = await response.Content.ReadFromJsonAsync<DiscoveryDoc>(cancellationToken: ct)
                ?? throw new ServiceTokenException(
                    "discovery_failed",
                    $"Discovery doc at {discoveryUrl} parsed as null.");

            if (string.IsNullOrWhiteSpace(doc.TokenEndpoint))
            {
                throw new ServiceTokenException(
                    "discovery_failed",
                    $"Discovery doc at {discoveryUrl} has no token_endpoint.");
            }

            _resolvedTokenEndpoint = doc.TokenEndpoint;
            _logger.LogDebug("Discovered token endpoint: {Endpoint}", _resolvedTokenEndpoint);
            return _resolvedTokenEndpoint;
        }
        finally
        {
            _discoveryLock.Release();
        }
    }

    /// <summary>
    /// Cache key. Scope order is normalised by sorting so <c>["a", "b"]</c> and
    /// <c>["b", "a"]</c> hit the same cached token. Equality is record-default.
    /// </summary>
    private static CacheKey MakeKey(string audience, IReadOnlyList<string> scopes) =>
        new(audience, string.Join(' ', scopes.OrderBy(s => s, StringComparer.Ordinal)));

    private sealed record CacheKey(string Audience, string NormalisedScopes);

    private sealed record CachedToken(string Value, DateTimeOffset ExpiresAt, int LifetimeSeconds)
    {
        public bool IsValid() => DateTimeOffset.UtcNow < ExpiresAt;

        public bool ShouldProactivelyRefresh(double fraction)
        {
            // True when we're past the configured fraction of the token's lifetime.
            // e.g. fraction=0.8 + 12h lifetime → returns true once we're past 9h36m.
            var refreshAt = ExpiresAt.AddSeconds(-LifetimeSeconds * (1 - fraction));
            return DateTimeOffset.UtcNow >= refreshAt;
        }
    }

    // Tiny private DTO for the discovery doc — only the field we need.
    private sealed class DiscoveryDoc
    {
        [System.Text.Json.Serialization.JsonPropertyName("token_endpoint")]
        public string? TokenEndpoint { get; set; }
    }
}
