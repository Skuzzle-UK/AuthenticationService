# Architecture

What's in this repo, what each piece does, and how a token gets from issuance to validation across services.

## Solution layout

### Production projects

| Project | Purpose |
|---|---|
| `AuthenticationService` | The HTTP API: registration, login, MFA, refresh (with rotation + reuse detection), per-device & all-device logout, password reset (also the account-unlock path), JWKS / OIDC discovery, `/oauth/token` for service-to-service. |
| `AuthenticationService.Shared` | DTOs, view models, and wire-contract constants (claim names, role values, policy names, auth scheme). Shared between the API, the client libraries, and any non-.NET clients (mobile, frontend, etc). |
| `AuthenticationService.TokenValidationLib` | Drop-in NuGet/project reference for **other microservices** that need to validate incoming JWTs. Provides `AddAuthenticationServiceJwt(...)` and `AddScopePolicy(...)`. Brings `AuthenticationService.Shared` in transitively so consumers get the constants without an extra reference. |
| `AuthenticationService.TokenClientLib` | Companion drop-in NuGet/project reference for services that need to **call other services** — gets a service-identity token via OAuth client-credentials, caches it, and stamps `Authorization: Bearer` on outgoing `HttpClient` calls. Provides `AddAuthenticationServiceTokenClient(...)` + `AddServiceToken("aud", scopes)`. Independent of the validation lib — consumers pick either, or both. |
| `AuthenticationService.ServiceDefaults` | Shared library that wires OpenTelemetry / health-checks / service-discovery defaults into any .NET project that joins the Aspire AppHost graph. Currently only the auth service itself; future microservices reference this for free. Production deploys do **not** ship Aspire — ServiceDefaults still adds OTel without it. |
| `ExampleConsumer` | A small minimal-API microservice that demonstrates the validation lib end-to-end. Useful as a smoke test and as a copy-paste starting point for new services. See the [end-to-end walk-through](getting-started.md#6-end-to-end-with-exampleconsumer). |

### Per-provider migrations

| Project | Purpose |
|---|---|
| `AuthenticationService.Migrations.MySql` | MySQL-specific EF Core migrations + model snapshot. |
| `AuthenticationService.Migrations.SqlServer` | SQL Server-specific migrations + snapshot. |
| `AuthenticationService.Migrations.Postgres` | PostgreSQL-specific migrations + snapshot. |

All three follow the same shape: their own `DesignTimeFactory` (so the EF CLI can target
each directly), an MSBuild `AfterTargets="Build"` step that copies the assembly into the
main project's `bin/` folder, and a runtime resolver hook in `Program.cs` that disk-probes
for the assemblies (the alternative — `ProjectReference` from the main project — would
cycle since each migrations project references the main one for `DatabaseContext`). EF
Core requires one model snapshot per provider per context, which is why we need the
separate assemblies. See [development/migrations.md](development/migrations.md) for the
workflow.

### Dev / test orchestration (not deployed)

| Project | Purpose |
|---|---|
| `AuthenticationService.AppHost` | .NET Aspire orchestrator. F5 here launches the auth service as a normal .NET process and spins up the configured DB + Redis + smtp4dev + Grafana as containers with connection strings auto-injected. DB defaults to MySQL; swap via `--db-provider=<SqlServer\|PostgreSQL>` arg or `INTEGRATION_DB_PROVIDER` env var. Aspire dashboard at `https://localhost:17282` shows live traces, logs, and metrics from every resource in the graph. **Dev/test only — never deployed.** |
| `Tests/AuthenticationService.TokenValidationLib.Tests` | Unit tests for the token-validation library (10 tests). |
| `Tests/AuthenticationService.TokenClientLib.Tests` | Unit tests for the token-client library (38 tests). |
| `Tests/AuthenticationService.Shared.Tests` | Unit tests for the shared DTOs / constants (78 tests). |
| `Tests/AuthenticationService.Tests` | Unit tests for the auth service — every controller endpoint, validator, middleware, helper, hosted-service sweep, etc. (493 tests). |
| `AuthenticationService.IntegrationTests` | End-to-end scenario tests using `Aspire.Hosting.Testing` to boot the whole AppHost graph in-process. Real MySQL, Redis, smtp4dev. (15 tests — see [development/testing.md](development/testing.md).) |

## Supported database providers

The auth service supports multiple EF Core providers, selected at startup via the
`DatabaseSettings:Provider` config value. The retry strategy and any provider-specific
workarounds (DateOnly value-converter etc.) are gated per provider.

| Provider | Allowed value | Retry strategy | Status |
|---|---|---|---|
| MySQL (Oracle) | `"MySQL"` | Custom `MySqlRetryingExecutionStrategy` (Oracle provider doesn't ship one) | Shipped |
| SQL Server | `"SqlServer"` | Built-in `EnableRetryOnFailure(5, 30s)` | Shipped |
| PostgreSQL | `"PostgreSQL"` | Built-in Npgsql `EnableRetryOnFailure(5, 30s)` | Shipped |

All entity timestamps are `DateTimeOffset` — the model is provider-agnostic in this regard,
and the strict `timestamptz` handling Npgsql 6+ ships by default is exactly what we want
(no `Npgsql.EnableLegacyTimestampBehavior` switch needed). On MySQL, columns are pinned to
`datetime(6)` via fluent configuration to preserve sub-second precision (Oracle's provider
defaults `DateTimeOffset` to plain `datetime` — second precision — which would be a silent
downgrade); SQL Server uses native `datetimeoffset`; PostgreSQL uses `timestamptz`.

When the model changes, you need to add migrations to every active provider —
[development/migrations.md](development/migrations.md) is the workflow runbook.

## How tokens flow

```
Microservice startup
  │
  └─ AddAuthenticationServiceJwt
        │
        └─ JwtBearer fetches:
             https://auth.example.com/.well-known/openid-configuration
                 ↓
             https://auth.example.com/.well-known/jwks.json
                 ↓
             Caches public EC key in memory (~24h refresh)

Request arrives with Authorization: Bearer eyJ...
  │
  ├─ JwtBearer reads kid from token header
  ├─ Looks up matching public key in cache
  ├─ Verifies ES256 signature
  ├─ Validates iss, aud, exp
  └─ Populates HttpContext.User and continues to [Authorize]
```

**No shared secrets.** The auth service is the only thing holding the private key. Consumers only ever see the public key via JWKS. See [concepts/security-model.md](concepts/security-model.md) for the full security stance.

## The two client libraries

The auth service's consumer surface is split across two independent NuGets:

| Library | Solves | Use when |
|---|---|---|
| **`AuthenticationService.TokenValidationLib`** | "Validate an incoming JWT" — JwtBearer wiring + scope-based authorisation policies. | Your service has HTTP endpoints that clients call with a `Bearer` token. |
| **`AuthenticationService.TokenClientLib`** | "Get a service-identity token for outgoing calls" — `(audience, scopes)`-keyed cache, proactive refresh, semaphore-protected concurrent refresh, OIDC discovery, RFC 6750 `invalid_token` retry-once. | Your service calls *another* service under its own identity (cron worker, message handler, service-to-service HTTP). |

A service that does both — exposes its own endpoints AND calls downstream services — pulls both libs. Most services need only one.

Both share the same `AuthenticationService` config section (`Authority` is reused), so adding the second lib later doesn't require new config infrastructure.

## Repository layout (top level)

```
AuthenticationService/                       ← The API (this is what gets deployed)
AuthenticationService.Shared/                ← DTOs + constants (NuGet-shaped)
AuthenticationService.TokenValidationLib/    ← Consumer lib: validate incoming JWTs
AuthenticationService.TokenClientLib/        ← Consumer lib: acquire outgoing tokens
AuthenticationService.ServiceDefaults/       ← OpenTelemetry + health-check defaults
AuthenticationService.AppHost/               ← Aspire orchestrator (dev/test only)
AuthenticationService.IntegrationTests/      ← E2E scenarios via Aspire.Hosting.Testing
ExampleConsumer/                             ← Demo consumer microservice
Tests/                                       ← Per-project xUnit suites
docs/                                        ← You are here
```

## Where to read next

- **Want to wire a new consumer?** → [consumers/validating-incoming-tokens.md](consumers/validating-incoming-tokens.md)
- **Need service-to-service calls?** → [consumers/outgoing-service-tokens.md](consumers/outgoing-service-tokens.md)
- **Want to understand a specific flow?** → [concepts/](concepts/) (user-auth-flows, refresh-rotation, service-to-service, security-model)
- **Deploying it?** → [operations/deployment.md](operations/deployment.md)
- **Looking up config keys?** → [reference/configuration.md](reference/configuration.md)
