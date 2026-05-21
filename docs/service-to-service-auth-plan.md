# Service-to-Service Authentication — Implementation Plan

**Status:** Phase 1 shipped (2026-05-21). Phase 2 deferred — "build when real demand arrives."
**Estimated effort:** ~4-5 focused days across two phases (Phase 1 actual: comparable)
**Tier:** 5 (multi-tenant features)
**Last updated:** 2026-05-21

> **Done (Phase 1):** `Clients` + `ClientScopes` entities + EF migrations; client-credentials
> grant at `POST /oauth/token` (`OAuthController`); admin client-management endpoints on
> `AdminController` (`POST /api/Admin/clients`, list / detail / disable / rotate-secret).
> Service-identity JWTs use the same JWKS as user tokens but a distinct claim shape (no
> `email` / `name`; `sub` carries the `client_id`; `scope` claim present). Incoming
> validation + `AddScopePolicy` helper shipped in
> `AuthenticationService.TokenValidationLib`. Outgoing typed-client pattern shipped in
> `AuthenticationService.TokenClientLib` (see [`service-token-client-plan.md`](service-token-client-plan.md)).
> `ExampleConsumer` demo wires both sides. Tests cover the `/oauth/token` happy path,
> rejected-credential paths, audience/scope enforcement, and end-to-end consumer flow.
>
> **Phase 2 (deferred):** JWT-bearer client assertions, mTLS, dynamic client registration.
> Tracked in the roadmap section of `TODO.md` — build when a consumer asks for it.

---

## Why we built this

Today, when one of our microservices calls another, it forwards the end-user's JWT. That has two real problems:

1. **Audit trail blames the user, not the calling service.** If the Orders service calls the Inventory service, the Inventory service sees the user's `sub` claim in the request — its logs say "user X read inventory" when actually "Orders service read inventory on behalf of user X." Compliance investigations get confused.

2. **No story for service-only calls.** Cron jobs, message handlers, scheduled syncs, and anything that runs without a user in the call chain has nowhere to get an identity from. Common workarounds — hardcoded API keys, skipping auth entirely, sharing a "system user" account — are all anti-patterns.

The standard answer is OAuth 2.0's **client credentials grant** (RFC 6749 §4.4). Each service has its own `client_id` + `client_secret`, exchanges them at the auth service's token endpoint for a service-identity JWT, and uses that for service-to-service calls. Consuming services validate via the same JWKS endpoint they already use for user tokens — they just see a different claim shape (no `email`, no `name`, `sub` is a client ID rather than a user ID).

---

## High-level shape

```
Orders service                AuthService                  Inventory service
     │                             │                              │
     │ POST /oauth/token            │                              │
     │ grant_type=client_credentials│                              │
     │ client_id=orders-service    │                              │
     │ client_secret=<secret>      │                              │
     │ audience=inventory-api      │                              │
     │ scope=inventory.read        │                              │
     │────────────────────────────>│                              │
     │                             │ validates credentials,       │
     │                             │ checks client→audience,      │
     │                             │ checks client→scope,         │
     │                             │ issues service JWT           │
     │ { access_token: "eyJ..." }  │                              │
     │<────────────────────────────│                              │
     │                             │                              │
     │            Authorization: Bearer <service JWT>             │
     │────────────────────────────────────────────────────────────>│
     │                                                            │
     │            validates via JWKS (existing path)              │
     │            checks scope via [Authorize(Policy = ...)]      │
     │            response                                         │
     │<────────────────────────────────────────────────────────────│
```

---

## Confirmed design decisions

Settled with the project owner (2026-05-08):

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Client storage | **DB-driven** | Live add/remove without redeploy; audit trail; needs admin endpoints |
| 2 | Scope model | **Resource-action** | `inventory.read`, `orders.write` — least privilege |
| 3 | Endpoint path | **`/oauth/token`** | RFC 6749 standard. Also advertise in OIDC discovery doc as `token_endpoint` |
| 4 | Token lifetime | **12 hours default**, configurable | Longer than user tokens (5 min) because services have no refresh-token machinery — they re-request. 12h matches batch / data-loader use cases |
| 5 | Client auth method | **Client secret** | Sent via HTTP Basic header (RFC 6749 §2.3.1). Other methods (JWT-bearer, mTLS) deferred to Phase 3+ |
| 6 | Audience model | **Per-service** (e.g., `inventory-api`) | Token is scoped to one audience. Multi-audience requests issued as separate tokens |
| 7 | OIDC discovery update | **Yes** | Adds `token_endpoint` and `grant_types_supported` to `/.well-known/openid-configuration` |
| 8 | Client library helper | **Yes** | `AuthenticationService.TokenValidationLib` exposes `AddScopePolicy(name, requiredScope)` |
| 9 | `ExampleConsumer` updates | **Yes** | Adds a `[Authorize(Policy = "example.read")]` endpoint as a demo |
| 10 | Integration tests | **Yes** | Scenario 9 (token endpoint happy path) + Scenario 10 (consumer rejects on missing scope) |

---

## Phase ordering — admin endpoints first

DB-driven clients implies admin endpoints to manage them. Those admin endpoints need an admin auth model, which currently barely exists (just the seeded admin account + `[Authorize(Policy = "AdminOnly")]` attribute). Before client management can land, we need a proper admin endpoint surface.

So the work splits into three phases, in this order:

| Phase | What | Effort |
|---|---|---|
| **Phase 0** | Admin endpoint foundation + user-admin endpoints + invitation flow | ~2 days |
| **Phase 1** | Service-to-service auth (clients + token endpoint + JWT shape + client lib helper) | ~2 days |
| **Phase 2** | Optional hardening: JWT-bearer client assertions, mTLS, dynamic registration | TBD |

---

## Phase 0 — Admin endpoint foundation

**Detailed plan lives in [`admin-endpoints-plan.md`](admin-endpoints-plan.md).** Summary only here.

Stands up the `AdminController` + supporting infrastructure that Phase 1 builds on top of. Nine endpoints covering paginated user list, user detail, admin-creates-user (with invitation email + basic page for the user to set their initial password), resend-invitation, lock, unlock, revoke-sessions, reset-mfa, force-password-reset, and audit-log read. Plus the public-facing `POST /api/registration/accept-invitation` endpoint and `Pages/AcceptInvitation.cshtml` landing page that complete the invitation flow.

Cross-cutting design (paged response envelope, Serilog SQL sink for audit, admin self-protection, new 5000-range security events, thin controller + service-layer split) is detailed in the plan doc.

**Estimated effort:** ~2 days (the invitation flow + basic page adds ~half a day to the original 1.5-day estimate).

---

## Phase 1 — Service-to-service auth

Depends on Phase 0 being landed (or at least the admin infrastructure ready to host client-management endpoints).

### Schema changes

New tables:

```sql
CREATE TABLE Clients (
    Id VARCHAR(255) PRIMARY KEY,              -- the client_id
    Name VARCHAR(255) NOT NULL,               -- human-readable label
    ClientSecretHash VARCHAR(512) NOT NULL,   -- BCrypt or ASP.NET Identity password hasher
    IsDisabled BOOLEAN NOT NULL DEFAULT FALSE,
    CreatedAt DATETIME(6) NOT NULL,
    LastUsedAt DATETIME(6) NULL,              -- updated on each successful token issue
    Description TEXT NULL,
    INDEX IX_Clients_IsDisabled (IsDisabled)
);

CREATE TABLE ClientScopes (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    ClientId VARCHAR(255) NOT NULL,
    Audience VARCHAR(255) NOT NULL,           -- e.g. "inventory-api"
    Scope VARCHAR(255) NOT NULL,              -- e.g. "inventory.read"
    FOREIGN KEY (ClientId) REFERENCES Clients(Id) ON DELETE CASCADE,
    UNIQUE KEY UX_ClientScopes (ClientId, Audience, Scope),
    INDEX IX_ClientScopes_ClientId (ClientId)
);
```

Entity classes follow the existing pattern (no DataAnnotations validation — handled by EF model config).

### New endpoint — `POST /oauth/token`

**Request** (RFC 6749 §4.4.2):

```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=client_credentials&audience=inventory-api&scope=inventory.read+inventory.write
```

Client credentials can also be in the body (per RFC §2.3.1) — accept both forms.

**Response (200):**

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 43200,
  "scope": "inventory.read inventory.write"
}
```

**Response (400 / 401):** RFC-shaped error envelope:

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

Standard RFC error codes: `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`.

### Validation flow inside the endpoint

1. Parse `grant_type` — must be `client_credentials`, else `unsupported_grant_type`
2. Extract `client_id` + `client_secret` from Authorization header or body
3. Look up `Clients` row; verify secret hash. Constant-time comparison
4. Reject if `IsDisabled` (returns `invalid_client` — don't reveal that the client exists)
5. Parse `audience` (required) and `scope` (required, space-separated)
6. For each scope, check `ClientScopes` has a row with the requested `(ClientId, Audience, Scope)` — else `invalid_scope`
7. Issue JWT (see shape below)
8. Update `Clients.LastUsedAt`
9. Log `SecurityEventIds.ClientCredentialsTokenIssued` with `client_id`, audience, scopes, IP

### Service-JWT claim shape

| Claim | Value | Notes |
|---|---|---|
| `iss` | `JWTSettings.ValidIssuer` | Same as user JWTs — same JWKS validates both |
| `aud` | The requested audience (e.g., `inventory-api`) | Per-service. Consumers configure `ValidAudience` to match |
| `sub` | The `client_id` | NOT a user ID. Consumers can distinguish by sub shape |
| `client_id` | Mirrors `sub` | Explicit. Some tools (Postman, Insomnia) prefer this |
| `scope` | Space-separated granted scopes | OAuth standard. Consumers parse and check |
| `iat` | Issued-at timestamp | Standard |
| `exp` | `iat + ClientCredentialsSettings.TokenLifetime` | Default 12h |
| `jti` | New `Guid.NewGuid()` | Standard. Lets revoke / replay-detect like user tokens |
| `azp` | `client_id` | Authorized party (OIDC core, §2) |

**Deliberately absent:** `email`, `name`, `role`, `sid`, `nbf` (issued = valid). User-token-specific claims must NOT be on service tokens — consumers should be able to write `if (HasClaim("email"))` to distinguish.

### Implementation files (Phase 1)

| File | Change |
|---|---|
| `Entities/Client.cs`, `Entities/ClientScope.cs` | New entities |
| `Storage/DatabaseContext.cs` | Add `DbSet<Client>`, `DbSet<ClientScope>`; configure relationships in `OnModelCreating` |
| New EF migration | Create the two tables |
| `Settings/ClientCredentialsSettings.cs` | `TokenLifetimeInHours` (default 12), `RequireHttpsOnTokenEndpoint` (default true) |
| `Services/IClientService.cs`, `Services/ClientService.cs` | Client lookup, secret verification, scope-check helpers |
| `Controllers/OAuthController.cs` | The `/oauth/token` endpoint |
| `Controllers/AdminController.cs` (extends Phase 0) | Client CRUD endpoints: `POST /api/Admin/clients`, `GET /api/Admin/clients`, `POST /api/Admin/clients/{id}/rotate-secret`, etc. |
| `Services/JWTService.cs` | Add `CreateServiceTokenAsync(client, scopes, audience)` — different claim shape from `CreateTokenAsync` |
| `Controllers/WellKnownController.cs` | OIDC discovery doc adds `token_endpoint` and `grant_types_supported: ["password", "client_credentials"]` |
| `Constants/SecurityEventIds.cs` | Add `ClientCredentialsTokenIssued`, `ClientCredentialsTokenDenied`, `ClientCreated`, `ClientSecretRotated`, `ClientDisabled` |
| `Constants/Scopes.cs` | Optional convention helper — common scope names for the platform |

### Client library helper

Consumers need to enforce scope-based authorization without writing custom handlers. The `AuthenticationService.TokenValidationLib` library exposes:

```csharp
services.AddAuthorization(opt =>
{
    opt.AddScopePolicy("inventory.read");
    opt.AddScopePolicy("inventory.write");
});
```

Implementation (small extension method):

```csharp
public static AuthorizationOptions AddScopePolicy(
    this AuthorizationOptions options,
    string requiredScope)
{
    options.AddPolicy(requiredScope, policy =>
        policy.RequireAssertion(ctx =>
        {
            var scopeClaim = ctx.User.FindFirst("scope")?.Value;
            if (string.IsNullOrWhiteSpace(scopeClaim)) return false;
            return scopeClaim.Split(' ').Contains(requiredScope, StringComparer.Ordinal);
        }));
    return options;
}
```

Usage in consumers:

```csharp
[ApiController]
[Route("api/[controller]")]
public class InventoryController : ControllerBase
{
    [HttpGet]
    [Authorize(Policy = "inventory.read")]
    public IActionResult List() => Ok(...);

    [HttpPost]
    [Authorize(Policy = "inventory.write")]
    public IActionResult Create([FromBody] InventoryItemDto dto) => ...;
}
```

### `ExampleConsumer` updates

Add a couple of scoped endpoints + show in the example walk-through how a service-to-service call flows:

```csharp
[Authorize(Policy = "example.read")]
[HttpGet("/example-read")]

[Authorize(Policy = "example.write")]
[HttpPost("/example-write")]
```

Update the consumer's startup to use the new `AddScopePolicy` helper. Update its README to walk through:
1. Curl `/oauth/token` for a service token
2. Use the token against `/example-read` — succeeds
3. Use the token against `/example-write` without the `example.write` scope — 403

### Admin endpoints for client management

Extending the `AdminController` from Phase 0:

| Endpoint | Body / Response |
|---|---|
| `POST /api/Admin/clients` | Create. Response includes the **one-time-display** secret (only shown once) |
| `GET /api/Admin/clients` | List (paginated, filterable by IsDisabled) |
| `GET /api/Admin/clients/{id}` | Detail (no secret, just metadata + scopes) |
| `POST /api/Admin/clients/{id}/rotate-secret` | Returns a new one-time-display secret |
| `POST /api/Admin/clients/{id}/disable` | Soft-delete (sets IsDisabled, keeps history) |
| `POST /api/Admin/clients/{id}/scopes` | Add a (audience, scope) tuple |
| `DELETE /api/Admin/clients/{id}/scopes/{audience}/{scope}` | Remove a scope |

The secret-display-once pattern is critical: the admin sees the raw secret on creation / rotation, copies it for the consuming service to use, and from then on only the hash is queryable. Forcing rotation if lost is by design.

### Tests for Phase 1

**Unit tests:**

- `ClientService`: secret-verification happy + wrong-password + disabled-client cases; scope-validation matrix
- `OAuthController`: every RFC error case (unsupported_grant_type, invalid_client, invalid_scope, etc.)
- `JWTService.CreateServiceTokenAsync`: claim shape, audience flows, scope claim format
- `Admin client CRUD`: create returns secret, list paginates, rotate invalidates old, disable doesn't delete

**Integration tests (new scenarios):**

- **Scenario 9** — `Service_Token_Endpoint_HappyPath`: register a client via admin endpoint → request a token → validate JWT → call an `ExampleConsumer` endpoint → 200
- **Scenario 10** — `Service_Token_Denied_When_Scope_Missing`: client has `inventory.read` but not `inventory.write` → token issued with `inventory.read` only → POST to `/inventory` returns 403 because scope check fails

These scenarios live alongside the existing 8.

### Rate limiting

`/oauth/token` joins `RateLimitPolicies.AuthStrict` — same 10/min per IP cap as `/authenticate`. Brute-force on guessed secrets is the main attack vector and 10/min stops it cold.

The integration test fixture's `--rate-limiting-disabled` flag still applies, so token requests across scenarios don't trip it.

---

## Phase 2 — Optional hardening

Defer until real demand. Options:

- **JWT-bearer client assertions** (RFC 7523). Service signs an assertion JWT with its own private key. Auth service validates the assertion. Used when client secrets are too leaky (e.g., mobile clients can't be trusted with a static secret).
- **mTLS client authentication** (RFC 8705). Service authenticates via TLS client certificate. Strongest assurance. Infrastructure-heavy — needs cert distribution + rotation tooling.
- **Dynamic client registration** (RFC 7591). Programmatic client creation via API instead of admin endpoints. Useful for multi-tenant SaaS where customers self-onboard.
- **Token introspection endpoint** (RFC 7662). Lets resource servers query the auth service "is this token still valid?" instead of relying on JWT validation alone. Useful for revocation propagation.

None of these are urgent. Each is a small addition once Phase 1 is solid.

---

## Risks & open questions

### Risks

1. **Token-endpoint DoS.** Every token request hits the DB twice (`Clients` lookup + scope check). If a misconfigured consumer hammers `/oauth/token` instead of caching the token, the auth service's DB load spikes. Mitigations: 12h default lifetime nudges toward caching; rate limiting; DB indexes on `Clients.Id` (PK already) and `ClientScopes.ClientId` (index in schema).

2. **Secret leakage.** Client secrets in env vars are durable — once leaked, they stay leaked until rotation. The admin "rotate secret" endpoint exists but operators have to remember to use it. Mitigation: surface a `LastRotatedAt` field on the Clients table and flag old secrets in admin UI.

3. **Service-token revocation.** User tokens have refresh-rotation + reuse-detection. Service tokens don't — they're valid for their full 12h regardless. Possible mitigations: (a) `/oauth/revoke` endpoint that adds the JTI to `RevokedTokens`; (b) per-client "rotate secret" propagates a global timestamp claim that consumers check (more invasive). Neither needed for v1; add if a real incident drives demand.

### Open questions

1. **Should consumers' `ValidAudience` config allow multiple audiences?** A service might accept both its primary audience (`inventory-api`) and a platform-wide one (`platform-api`) for backward compat. Probably yes — `TokenValidationParameters.ValidAudiences` is a list, not single-valued.

2. **How does an existing user-JWT consumer service handle service tokens?** Strictly speaking, current `ExampleConsumer` and similar will validate either kind because they share the same issuer + JWKS. That's fine — endpoints currently gated by `[Authorize]` work for both. The new scope-based policies are additive.

3. **Multi-audience tokens?** RFC allows `aud` to be a JSON array. We're issuing single-audience tokens for simplicity. If a future "platform admin" service needs cross-cutting access, we might revisit — but it's easier to issue multiple single-audience tokens than one multi-audience.

---

## Effort estimate

| Phase | Estimate (focused work) |
|---|---|
| Phase 0 — admin endpoints (incl. invitation flow) | 2 days |
| Phase 1 — service-to-service auth | 2 days |
| Phase 2 — optional hardening | per-feature, TBD |

**Phase 0 + 1 together: ~4 focused days.** Plus the usual code-review / iteration overhead, call it a working week.

---

## Definition of done

For Phase 0:
- Admin endpoints land with `[Authorize(Policy = "AdminOnly")]`
- Full unit-test coverage
- One integration test scenario covering the admin → user lifecycle
- README updated with admin endpoint table + usage example

For Phase 1:
- `Clients` + `ClientScopes` tables migrated
- `/oauth/token` endpoint serves valid client_credentials grants
- Service-JWT claim shape passes consumer validation
- `AuthenticationService.TokenValidationLib` exposes `AddScopePolicy` helper
- `ExampleConsumer` demonstrates scope-gated endpoints
- Admin endpoints for client CRUD live
- Scenarios 9 & 10 green in CI
- OIDC discovery doc advertises `token_endpoint`
- README has a new "service-to-service auth" section walking through the end-to-end flow

---

## Reference materials

- [RFC 6749 — OAuth 2.0 Framework](https://datatracker.ietf.org/doc/html/rfc6749)
  - §4.4 Client Credentials grant
  - §2.3 Client Authentication
- [RFC 7523 — JWT-bearer Client Assertions](https://datatracker.ietf.org/doc/html/rfc7523) (Phase 2)
- [RFC 8705 — mTLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705) (Phase 2)
- [OpenID Connect Core 1.0 §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) — `azp` claim semantics
