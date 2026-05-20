# Service-Token Client Helper — Implementation Plan

**Status:** Shipped (2026-05-20)
**Estimated effort:** ~0.5 day (actual: comparable)
**Depends on:** Phase 1 of [`service-to-service-auth-plan.md`](service-to-service-auth-plan.md) (committed)
**Last updated:** 2026-05-20

> **Done:** lib split into `AuthenticationService.TokenValidationLib` (incoming JWTs +
> `AddScopePolicy`) and `AuthenticationService.TokenClientLib` (outgoing service tokens).
> 38 unit tests in `Tests/AuthenticationService.TokenClientLib.Tests/` cover the provider
> cache + refresh + discovery + retry contract and the handler 401-retry path. Two
> end-to-end integration tests in `AuthenticationService.IntegrationTests/Scenarios/ServiceTokenClientIntegrationTests.cs`
> exercise the full flow against the live auth service + an in-process TestServer
> downstream (cache-hit verification via jti equality, retry-on-401 via jti inequality).
> Main README has a "Same flow from .NET — the typed-client shape" subsection beside the
> existing curl walkthrough.

---

## Why we're building this

Phase 1 stood up the auth-service side of OAuth client-credentials — a working `/oauth/token` endpoint, admin client management, and the `AddScopePolicy` helper for **incoming** scope checks on resource servers. The README walk-through shows how to fetch a token via `curl`.

What we *don't* have is the consumer-side ergonomics. When a real service (Orders, a cron worker, a message handler) needs to call another service, it has to:

1. Hold its `client_id` + `client_secret` somewhere safe
2. POST form-encoded credentials to `/oauth/token`
3. Parse the response
4. Cache the token until close to expiry, with thread-safety + concurrent-refresh protection
5. Stamp `Authorization: Bearer ...` on every outgoing `HttpClient` call
6. Detect downstream 401 and refresh

That's the kind of boilerplate that gets re-implemented badly across the platform. The standard .NET pattern is a typed `DelegatingHandler` + cache that consumers wire into their existing `HttpClient` registrations. This plan adds exactly that, in `AuthenticationService.TokenClientLib`.

End-state ergonomics for a consumer:

```csharp
// In Orders service's Program.cs
services.AddAuthenticationServiceTokenClient(
    config.GetSection("AuthenticationService"));

services.AddHttpClient<InventoryClient>(c =>
    {
        c.BaseAddress = new Uri(config["Inventory:BaseUrl"]!);
    })
    .AddServiceToken(audience: "inventory-api",
                     scopes: ["inventory.read", "inventory.write"]);
```

…and every call through `InventoryClient` arrives at Inventory with a fresh valid Bearer token.

---

## High-level shape

Three moving pieces inside `AuthenticationService.TokenClientLib`:

| Component | Responsibility |
|---|---|
| `IServiceTokenProvider` (singleton) | Caches tokens keyed by `(audience, scopes)`. Refreshes proactively at ~80% of `expires_in`. Serialises concurrent refreshes via a per-key `SemaphoreSlim` so a thundering herd at expiry hits `/oauth/token` exactly once. |
| `ServiceTokenHandler` (per-typed-client `DelegatingHandler`) | Asks the provider for a token, stamps the `Authorization` header, sends. On a 401 from the downstream, invalidates the cached token and retries once. |
| `AddServiceToken(audience, scopes)` extension | Sugar on `IHttpClientBuilder` — registers a per-typed-client handler with the right audience/scopes baked in. |

Plus config: a `ServiceTokenClientOptions` settings class extending what's already in `AuthenticationServiceOptions`.

---

## Confirmed design decisions

Settled with the project owner (2026-05-19):

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Token cache scope | **In-memory singleton, per-process** | Each consuming process holds its own tokens. Multi-replica deployments will each cache independently — that's fine, tokens are cheap to mint. No Redis/external cache. |
| 2 | Refresh trigger | **Proactive at 80% of `expires_in`** | A handler that sees a token with <20% lifetime remaining triggers a background refresh, returns the still-valid current token, swaps when refresh completes. Falls back to synchronous refresh when token is already expired (cold start, long-idle process). |
| 3 | Concurrent-refresh protection | **`SemaphoreSlim` per `(audience, scopes)` key** | Thundering-herd protection — only one in-flight token request per key. Other callers await the same Task. |
| 4 | Token endpoint discovery | **Use OIDC discovery doc** | Hit `/.well-known/openid-configuration`, cache the `token_endpoint`. Means changing the URL on the server doesn't break consumers. JwtBearer already does this for JWKS; we do the same for the token endpoint. |
| 5 | Failure on `/oauth/token` 4xx | **Bubble up immediately, don't retry** | 4xx means config / credentials / scope is wrong — retrying won't help. Surface a typed exception (`ServiceTokenException` carrying the OAuth `error` code) so callers can distinguish from network errors. |
| 6 | Failure on `/oauth/token` 5xx or transient network | **Exponential backoff, configurable max retries (default 3)** | Transient backend issues shouldn't take the consumer down. Standard handler pattern. |
| 7 | Downstream 401 with `invalid_token` | **Invalidate cache + single retry** | Caches can go stale if the token is somehow revoked or the auth service's keys rotate. Retry once with a fresh token; a second 401 means the credentials themselves don't work and bubbles up. |
| 8 | Config storage | **`ClientId` + `ClientSecret` on a new `ServiceTokenClientOptions`** | Keep the existing `AuthenticationServiceOptions` clean — that's resource-server config. Outgoing-token concerns are orthogonal. |
| 9 | Secret-from-where | **Configuration first, with explicit support for env vars / user secrets / secret store** | Standard ASP.NET Core config-binding. `ClientSecret` MUST be supplied (settings validator throws at startup otherwise). |
| 10 | Per-call audience/scopes vs per-handler | **Per-handler — baked at registration time** | `AddServiceToken("inventory-api", ...)` registers a handler specifically for the inventory-api audience. A consumer calling two services has two typed clients with two handlers. Matches the "tokens are single-audience" Phase 1 design. |

---

## Implementation plan

### New files in `AuthenticationService.TokenClientLib/`

(Newly created sibling project — split out from the original combined `AuthenticationService.Client` so consumers can opt into the validation lib, the client lib, or both, independently.)

| File | Purpose |
|---|---|
| `ServiceTokenClientOptions.cs` | `Authority` (reuse from existing), `ClientId`, `ClientSecret`, optional `TokenEndpointOverride` (skip discovery), retry/refresh tuning. |
| `IServiceTokenProvider.cs` | `Task<string> GetTokenAsync(string audience, IReadOnlyList<string> scopes, CancellationToken ct)` + `void Invalidate(string audience, IReadOnlyList<string> scopes)`. |
| `ServiceTokenProvider.cs` | The cache + refresh logic. `Dictionary<CacheKey, CachedToken>` + per-key semaphore. |
| `ServiceTokenHandler.cs` | `DelegatingHandler`. Constructor params: audience + scopes + `IServiceTokenProvider`. |
| `ServiceTokenException.cs` | Typed exception with OAuth `error` code + description. |
| `ServiceCollectionExtensions.cs` (extend) | `AddAuthenticationServiceTokenClient(IConfiguration)` — registers provider + options + the discovery HttpClient. |
| `HttpClientBuilderExtensions.cs` | `AddServiceToken(this IHttpClientBuilder, string audience, params string[] scopes)` — adds the handler. |

### Settings shape

```csharp
public class ServiceTokenClientOptions
{
    [Required] public string? Authority { get; set; }      // reuse — same Authority as AuthenticationServiceOptions
    [Required] public string? ClientId { get; set; }
    [Required] public string? ClientSecret { get; set; }
    public string? TokenEndpointOverride { get; set; }     // skip discovery if set (test convenience)
    public bool RequireHttpsMetadata { get; set; } = true;
    public double RefreshAtFractionOfLifetime { get; set; } = 0.8;
    public int MaxRetriesOnTransient { get; set; } = 3;
}
```

### Token cache shape

```csharp
private sealed record CacheKey(string Audience, string ScopesNormalised);

private sealed record CachedToken(string Value, DateTimeOffset ExpiresAt)
{
    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
    public bool ShouldProactivelyRefresh(double fraction)
        => DateTimeOffset.UtcNow >= /* expires - (lifetime * (1 - fraction)) */;
}
```

`ScopesNormalised` is the scope list sorted + joined with spaces so `["read", "write"]` and `["write", "read"]` cache to the same key.

### Discovery

On first token request, the provider hits `${Authority}/.well-known/openid-configuration`, caches the response, reads `token_endpoint` and uses it for every subsequent request. Re-fetches if a 404 ever comes back (unlikely; means a deploy changed the path).

### Token-request shape

POST to the discovered (or overridden) token endpoint:

```
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=client_credentials&audience=<audience>&scope=<space-separated>
```

Parse response per the existing `OAuthTokenResponse` shape (already in `AuthenticationService.Shared`). Store `access_token` + compute `ExpiresAt = utcnow + expires_in seconds`.

### Handler logic

```csharp
public class ServiceTokenHandler : DelegatingHandler
{
    private readonly IServiceTokenProvider _provider;
    private readonly string _audience;
    private readonly IReadOnlyList<string> _scopes;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var token = await _provider.GetTokenAsync(_audience, _scopes, ct);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await base.SendAsync(request, ct);

        if (response.StatusCode == HttpStatusCode.Unauthorized &&
            LooksLikeInvalidToken(response))
        {
            _provider.Invalidate(_audience, _scopes);
            response.Dispose();
            token = await _provider.GetTokenAsync(_audience, _scopes, ct);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            response = await base.SendAsync(request, ct);
        }

        return response;
    }
}
```

`LooksLikeInvalidToken` inspects `WWW-Authenticate` for `error="invalid_token"` per RFC 6750 §3.

### Consumer-side ergonomics

```csharp
// Program.cs
services.AddAuthenticationServiceTokenClient(config.GetSection("AuthenticationService"));

services.AddHttpClient<InventoryClient>(c =>
    {
        c.BaseAddress = new Uri(config["Inventory:BaseUrl"]!);
    })
    .AddServiceToken("inventory-api", ["inventory.read", "inventory.write"]);
```

```csharp
// InventoryClient.cs (typed client written by the consumer team)
public class InventoryClient
{
    private readonly HttpClient _http;
    public InventoryClient(HttpClient http) { _http = http; }

    public Task<Inventory?> GetItemAsync(int id, CancellationToken ct = default)
        => _http.GetFromJsonAsync<Inventory>($"items/{id}", ct);
    // ↑ Authorization header gets stamped automatically by the handler.
}
```

For manual usage (not through HttpClient — e.g., a SignalR client, gRPC client):

```csharp
public class GrpcInventoryClient
{
    private readonly IServiceTokenProvider _tokenProvider;
    private readonly InventoryService.InventoryServiceClient _grpc;

    public async Task<Item> GetItemAsync(int id)
    {
        var token = await _tokenProvider.GetTokenAsync("inventory-api", ["inventory.read"]);
        var headers = new Metadata { { "Authorization", $"Bearer {token}" } };
        return await _grpc.GetItemAsync(new GetItemRequest { Id = id }, headers);
    }
}
```

---

## Tests

### Unit tests (`Tests/AuthenticationService.TokenClientLib.Tests/`)

(New test project — counterpart of the existing `Tests/AuthenticationService.TokenValidationLib.Tests/` for the renamed validation lib.)

The client lib already has a test project. Add to it:

- `ServiceTokenProvider`:
  - First call fetches via HTTP, returns token
  - Second call within `expires_in * RefreshAtFractionOfLifetime` returns cached
  - Call past 80% of lifetime triggers background refresh, still returns current
  - Call past expiry blocks on refresh, returns new
  - 100 concurrent calls during a refresh → exactly one HTTP request to `/oauth/token`
  - `Invalidate` causes the next call to re-fetch
  - Different `(audience, scopes)` keys cache independently
  - Scope-order independence (sorted before keying)
  - 4xx response → throws `ServiceTokenException` with the OAuth error code
  - 5xx → retries with backoff up to `MaxRetriesOnTransient`, then throws
  - Discovery hit at startup, cached after

- `ServiceTokenHandler`:
  - Happy path: stamps `Authorization: Bearer <token>`, sends, returns response
  - Downstream 401 with `WWW-Authenticate: Bearer error="invalid_token"` → invalidates + retries once
  - Downstream 401 with different `WWW-Authenticate` → no retry, returns the 401
  - Two consecutive 401s → bubbles second one up
  - Provider throws → bubbles up; no request sent

Mock the HTTP transport via `HttpMessageHandler` to keep tests offline + deterministic.

### Integration scenario 15

End-to-end against the real auth service + a mock downstream:

1. Spin up a stub `MockResource` HTTP server in-process that validates JWTs via the real JWKS endpoint
2. Configure a typed client with `AddServiceToken("mock-resource", ["scope.x"])`
3. Make a call → assert it succeeded → assert the auth service issued one token
4. Make a second call immediately → assert no new token issue (cached)
5. Stub the auth service to advance the system clock past expiry → next call refreshes

Could also exercise the 401-retry path by having the mock reject the first token, accept the second.

---

## Open questions

1. **Should the provider have a public "warm up" method?**
   On startup a service might want to pre-fetch tokens for its known downstream audiences so the first real request doesn't pay the cold-start latency. Easy to add: `await provider.WarmUpAsync("inventory-api", ["read", "write"])`.

2. **Should the handler honour cancellation propagation through retries?**
   Currently the retry on 401 re-sends with the same cancellation token. If the original request was already cancelled (e.g., user-driven request timeout), the retry will cancel too. Probably the right default.

3. **Should `ServiceTokenException` distinguish "config wrong" from "network down"?**
   Maybe sub-types: `ServiceTokenConfigException` (4xx — fix config) vs `ServiceTokenTransientException` (5xx / network — wait and retry). Callers can `catch` either.

4. **Per-call scope override?**
   The current design bakes scopes into the handler. If a single typed client needs to make calls under different scope sets (e.g., a read-only request vs an admin write request), the consumer either registers two typed clients or somehow opts into per-call scopes. Probably "register two typed clients" is the right answer; opens up a `[ServiceTokenScopes]` attribute later if needed.

5. **How does this interact with retry policies in `Microsoft.Extensions.Http.Resilience`?**
   The resilience middleware also wraps `HttpClient`. Order matters: scope-token handler should be inside the resilience handler so retries get fresh tokens if needed. Document the registration order.

---

## Definition of done

- `AuthenticationService.TokenClientLib` has `IServiceTokenProvider`, `ServiceTokenHandler`, `ServiceTokenException`, plus the two extension methods (`AddAuthenticationServiceTokenClient`, `AddServiceToken`)
- Settings class binds + validates at startup (missing `ClientSecret` is a startup-time exception, not a runtime surprise)
- OIDC discovery used by default; override available for tests
- 401-invalid_token retry once works end-to-end
- ~12 unit tests cover the contract above
- Integration scenario 15 green against real MySQL + a mock resource
- `ExampleConsumer` README updated with a typed-client section alongside the curl walkthrough — show both shapes side by side so consumers pick the right one for their use case
