# Outgoing service tokens (TokenClientLib)

Your microservice needs to call *another* microservice under its own identity (cron worker, message handler, service-to-service HTTP). You don't have a user JWT — you have a `client_id` + `client_secret`. This page is how to wire that up cleanly.

## The two viewpoints

Two paths to a working call: the **wire-level walk-through** (curl, see exactly what's on the network) and the **production-shape .NET integration** (typed `HttpClient` + `TokenClientLib`). The walk-through is for understanding; the .NET integration is what real consumers actually do.

## Wire-level walk-through (curl)

End-to-end flow against the running auth service + `ExampleConsumer`:

**1. Create a client (one-time admin step).**

The auth service admin creates the client via `POST /api/Admin/clients` (use Swagger, authenticated as the seeded admin):

```json
{
  "id": "example-consumer",
  "name": "Example consumer service",
  "description": "Demo client for the s2s walk-through",
  "scopes": [
    { "audience": "example-consumer", "scope": "example.read" }
  ]
}
```

The response carries the **plaintext client secret** — capture it now, it's never shown again. Only the hash is persisted.

**2. Get a token.**

The consuming service POSTs form-encoded credentials to `/oauth/token`:

```bash
curl -X POST https://localhost:53217/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "example-consumer:<the-secret-from-step-1>" \
  -d "grant_type=client_credentials&audience=example-consumer&scope=example.read"
```

The response is the standard OAuth shape (RFC 6749 §5.1):

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 43200,
  "scope": "example.read"
}
```

**3. Call the downstream with the service token.**

```bash
curl https://localhost:50500/example-read \
  -H "Authorization: Bearer eyJhbGciOi..."
```

Returns 200 with the client_id + granted scopes from the token.

**4. Negative test: scope-denied.**

Try the same token against `/example-write`:

```bash
curl -X POST https://localhost:50500/example-write \
  -H "Authorization: Bearer eyJhbGciOi..."
```

Returns **403 Forbidden** — the token doesn't carry `example.write`. To make it work, the admin would need to add `(example-consumer, example.write)` to the client's scope set (`POST /api/Admin/clients/example-consumer/scopes`), then the consumer would request a fresh token with both scopes.

**5. Discovery.**

The token endpoint is advertised in the OIDC discovery doc at `/.well-known/openid-configuration`:

```json
{
  "issuer": "https://auth.example.com",
  "token_endpoint": "https://localhost:53217/oauth/token",
  "grant_types_supported": ["client_credentials"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  ...
}
```

Consumers that already configure `Authority` for JWKS automatically pick this up.

## Production-shape .NET integration

The curl walkthrough is the wire-level view. In real consumer code you don't hand-roll Basic auth + form encoding + cache + concurrent-refresh protection + 401 retry — you use the **`AuthenticationService.TokenClientLib`** drop-in, which handles all of that and exposes a one-line `AddServiceToken("audience", "scope")` extension on `IHttpClientBuilder`.

### Configure

```jsonc
// Orders service's appsettings.json — same config section as the validation lib.
// The ClientSecret should come from user-secrets / env var / secret store in real deployments.
"AuthenticationService": {
  "Authority": "https://auth.example.com",
  "Audience": "orders-api",                  // for AddAuthenticationServiceJwt (incoming validation)
  "Issuer":   "https://auth.example.com",
  "ClientId":     "example-consumer",        // for AddAuthenticationServiceTokenClient (outgoing fetch)
  "ClientSecret": "<the-secret-from-step-1>" // ← keep this out of source control
}
```

### Wire up

```csharp
// Program.cs
using AuthenticationService.TokenClientLib;

var builder = WebApplication.CreateBuilder(args);

// Outgoing-token plumbing. Provider is a singleton (process-wide cache); discovery doc +
// token endpoint are resolved on the first call and cached for the process lifetime.
builder.Services.AddAuthenticationServiceTokenClient(
    builder.Configuration.GetSection("AuthenticationService"));

// Typed client for the downstream we want to call. Anything injected with InventoryClient
// gets an HttpClient that auto-stamps `Authorization: Bearer <jwt>` on every outgoing
// request. Audience + scopes are baked in at registration — if you call two services with
// different scope sets, register two typed clients.
builder.Services
    .AddHttpClient<InventoryClient>(c => c.BaseAddress = new Uri("https://inventory.example.com"))
    .AddServiceToken(audience: "inventory-api", scopes: "inventory.read");

// (The above is independent of AddAuthenticationServiceJwt — register that too if the same
// service ALSO needs to validate incoming tokens.)

var app = builder.Build();
app.Run();
```

### Use it

```csharp
// InventoryClient.cs — written by the consumer team. No auth code anywhere.
public class InventoryClient(HttpClient http)
{
    public Task<InventoryItem?> GetItemAsync(int id, CancellationToken ct = default)
        => http.GetFromJsonAsync<InventoryItem>($"items/{id}", ct);
    //   ↑ Authorization: Bearer <fresh service JWT> gets stamped automatically by the handler.
}
```

## What the lib gives you for free

What the curl flow doesn't show, but real consumers need:

- **In-memory token cache keyed by `(audience, scopes)`** — every call after the first hits the cache, the auth service is bothered exactly once per `expires_in` (default 12h).
- **Proactive refresh at 80% of lifetime** — the token swap happens in the background; user-facing calls never block on the refresh.
- **Per-key `SemaphoreSlim`** — a thundering herd at expiry hits `/oauth/token` exactly once. The other callers wake up and find the freshly-minted token in the cache.
- **Stale-token recovery** — if a downstream returns 401 with `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750 §3), the handler invalidates the cached token and retries once with a fresh one. A second 401 bubbles up — credentials don't work and re-fetching can't fix it.
- **OIDC discovery** — `token_endpoint` is resolved via `/.well-known/openid-configuration` on the first call, cached after. Operators can change the URL on the auth service without redeploying consumers.
- **Bounded retries on 5xx / transient network** — exponential backoff (250ms, 500ms, 1s, …, capped 30s) up to `MaxRetriesOnTransient` (default 3). 4xx responses bubble up immediately — they indicate config / credential errors retrying can't fix.

## Non-HttpClient callers (gRPC, SignalR)

You can inject `IServiceTokenProvider` directly and ask for a token by hand:

```csharp
public class GrpcInventoryClient(IServiceTokenProvider tokenProvider, Inventory.InventoryClient grpc)
{
    public async Task<Item> GetItemAsync(int id, CancellationToken ct = default)
    {
        var token = await tokenProvider.GetTokenAsync("inventory-api", ["inventory.read"], ct);
        var headers = new Metadata { { "Authorization", $"Bearer {token}" } };
        return await grpc.GetItemAsync(new GetItemRequest { Id = id }, headers, cancellationToken: ct);
    }
}
```

The provider's cache + refresh / dedup / retry semantics apply identically — you just stamp the header yourself.

## Tuning

All knobs live on `ServiceTokenClientOptions` (the config section bound by `AddAuthenticationServiceTokenClient`):

| Key | Default | Notes |
|---|---|---|
| `Authority` | (required) | Base URL of the auth service. Shared with the validation lib. |
| `ClientId` | (required) | The client_id from the admin `POST /api/Admin/clients` step. |
| `ClientSecret` | (required) | The plaintext secret from the same step. **Secret material — source from a secret store.** |
| `TokenEndpointOverride` | (none) | Skip OIDC discovery; use this URL directly. Useful for tests + air-gapped environments. |
| `RequireHttpsMetadata` | `true` | Whether discovery requires HTTPS. Flip off for local-dev HTTP. |
| `RefreshAtFractionOfLifetime` | `0.8` | Fraction of `expires_in` past which the cache proactively refreshes. |
| `MaxRetriesOnTransient` | `3` | Retries against `/oauth/token` on 5xx / network error. 4xx is never retried. |

## See also

- [consumers/claim-shapes.md](claim-shapes.md) — what's in a service token vs a user token, and how to distinguish them downstream
- [concepts/service-to-service.md](../concepts/service-to-service.md) — the design behind the s2s flow
