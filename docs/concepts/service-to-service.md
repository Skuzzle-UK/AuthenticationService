# Service-to-service auth

How the OAuth client-credentials flow is shaped in this codebase, and why the design landed where it did. For the wiring-up walk-through see [consumers/outgoing-service-tokens.md](../consumers/outgoing-service-tokens.md).

## Why s2s instead of forwarding the user's JWT

Forwarding the user's JWT downstream looks tempting — it preserves user identity end-to-end. Two real problems:

1. **Audit trail blames the user, not the calling service.** If Orders calls Inventory with the user's JWT, Inventory's logs say "user X read inventory" when actually "Orders read inventory on behalf of user X." Compliance investigations get confused.
2. **No story for service-only calls.** Cron jobs, message handlers, scheduled syncs run without a user. Common workarounds — hardcoded API keys, skipping auth, sharing a "system user" — are all anti-patterns.

The standard answer is OAuth 2.0's **client-credentials grant** (RFC 6749 §4.4). Each service has its own `client_id` + `client_secret`, exchanges them at `/oauth/token` for a service-identity JWT, and uses that for outgoing calls. Consuming services validate via the same JWKS endpoint they already use for user tokens — they just see a different claim shape (see [consumers/claim-shapes.md](../consumers/claim-shapes.md)).

## End-to-end flow

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

## Design decisions

These are the calls that shape every other piece of the implementation. The plan doc ([`docs/service-to-service-auth-plan.md`](../service-to-service-auth-plan.md)) has the full settle-record; the table here is the gist.

| # | Decision | Choice | Why |
|---|---|---|---|
| 1 | Client storage | **DB-driven** (`Clients` + `ClientScopes` tables) | Live add/remove without redeploy; audit trail; admin endpoints can manage. |
| 2 | Scope model | **Resource-action** (`inventory.read`, `orders.write`) | Least privilege per call; easy to gate on the consumer side. |
| 3 | Endpoint path | **`/oauth/token`** | RFC 6749 standard. Also advertised in the OIDC discovery doc as `token_endpoint`. |
| 4 | Token lifetime | **12 hours default**, configurable | Longer than user tokens (5 min) because services have no refresh-token machinery — they re-request. 12h matches batch / data-loader use cases. |
| 5 | Client auth method | **Client secret** | Sent via HTTP Basic header (RFC 6749 §2.3.1). JWT-bearer assertions and mTLS deferred to Phase 2. |
| 6 | Audience model | **Per-service** (e.g. `inventory-api`) | Token is scoped to one audience. Multi-audience requests issued as separate tokens. |
| 7 | OIDC discovery | **Yes** | Adds `token_endpoint` and `grant_types_supported` to `/.well-known/openid-configuration`. |
| 8 | Client library | **`TokenClientLib`** — separate from `TokenValidationLib` | A service may need either, both, or neither. Splitting keeps the dependency graph minimal. |
| 9 | Scope authorisation | **`AddScopePolicy(scope)`** helper in TokenValidationLib | Consumer-side policy registration; the JWT's `scope` claim drives the assertion. |
| 10 | Rate limiting | **`auth-strict` (10/min per IP)** on `/oauth/token` | Brute-forcing client secrets is the main attack vector. 10/min stops it cold. |

## Service-JWT claim shape

Stamped by `JWTService.CreateServiceTokenAsync`. The full table is in [consumers/claim-shapes.md](../consumers/claim-shapes.md); the short version:

- `iss`, `aud`, `exp`, `iat`, `jti` — standard.
- `sub` = `client_id` (not a user id).
- `client_id`, `azp` mirror `sub`.
- `scope` — space-separated granted scopes.
- **No `email`, `name`, `role`, `sid`, `nbf`.** Service tokens deliberately omit user-token claims so consumers can distinguish kinds by their absence.

## Admin surface for client management

Phase 0's admin infrastructure carries the client CRUD:

| Endpoint | What |
|---|---|
| `POST /api/Admin/clients` | Create. Response includes the **one-time-display** secret (only shown once). |
| `GET /api/Admin/clients` | List (paginated, filterable by `IsDisabled`). |
| `GET /api/Admin/clients/{id}` | Detail (no secret, just metadata + scopes). |
| `POST /api/Admin/clients/{id}/rotate-secret` | Returns a new one-time-display secret. |
| `POST /api/Admin/clients/{id}/disable` | Soft-delete (sets `IsDisabled`, keeps history). |
| `POST /api/Admin/clients/{id}/scopes` | Add a `(audience, scope)` tuple. |
| `DELETE /api/Admin/clients/{id}/scopes/{audience}/{scope}` | Remove a scope. |

The **secret-display-once pattern** is critical: the admin sees the raw secret on creation / rotation, copies it for the consuming service to use, and from then on only the hash is queryable. Forcing rotation if lost is by design.

## Validation flow inside `/oauth/token`

1. Parse `grant_type` — must be `client_credentials`, else `unsupported_grant_type`.
2. Extract `client_id` + `client_secret` (Basic header preferred; body fallback per RFC §2.3.1).
3. Look up `Clients` row; verify secret hash. Constant-time compare.
4. Reject if `IsDisabled` (returns `invalid_client` — don't reveal that the client exists).
5. Parse `audience` (required) and `scope` (required, space-separated).
6. For each scope, check `ClientScopes` has a row with `(ClientId, Audience, Scope)` — else `invalid_scope` (all-or-nothing, no partial grants).
7. Issue JWT via `JWTService.CreateServiceTokenAsync`.
8. Update `Clients.LastUsedAt` (admin visibility into client activity).
9. Log `ClientCredentialsTokenIssued` (event ID 5001) with client_id, audience, scopes, IP.

Both the happy path and every error branch are covered by integration tests 10 + 11 (`OAuthClientCredentialsTests`, `OAuthScopeAuthorizationTests`).

## Open items (Phase 2)

Deferred until real demand drives them:

- **JWT-bearer client assertions** (RFC 7523). Service signs an assertion JWT with its own private key. Useful when client secrets are too leaky.
- **mTLS client authentication** (RFC 8705). Strongest assurance; infrastructure-heavy.
- **Dynamic client registration** (RFC 7591). Programmatic client creation. Useful for multi-tenant SaaS self-onboard.
- **Token introspection endpoint** (RFC 7662). Lets resource servers query "is this token still valid?" for revocation propagation.

None blocks shipping today.
