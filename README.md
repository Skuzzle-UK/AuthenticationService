# AuthenticationService

[![CI](https://github.com/Skuzzle-UK/AuthenticationService/actions/workflows/ci.yml/badge.svg)](https://github.com/Skuzzle-UK/AuthenticationService/actions/workflows/ci.yml)

Centralised identity & access service for the platform. Issues short-lived ES256-signed JWTs in two flavours — end-user tokens and service-identity tokens — and publishes a JWKS endpoint so every consuming microservice can validate them without ever holding the signing key. Ships a pair of drop-in client libraries for the consumer side: one to validate incoming tokens, one to acquire outgoing ones.

The service is dev-orchestrated with [.NET Aspire](https://learn.microsoft.com/en-us/dotnet/aspire/) and deploys as a plain ASP.NET Core process — Aspire is the local front-end, not the runtime.

## Features

- **User authentication** — registration with email confirmation, login (optional MFA), refresh-token rotation with reuse-detection cascade, password reset, indefinite-lockout / unlock flows, per-device + all-device logout.
- **Service-to-service authentication** — OAuth 2.0 client-credentials grant. Clients are authorised by `(audience, scope)` tuples; tokens carry an explicit `client_id` claim so the consuming service can distinguish service identities from user identities.
- **No shared secrets** — consumers validate via the published JWKS (`/.well-known/jwks.json`). The auth service is the only holder of the private key. Algorithm is restricted to ES256 at validation time to defeat algorithm-confusion attacks.
- **Drop-in client libraries**:
  - `AuthenticationService.TokenValidationLib` — `AddAuthenticationServiceJwt(...)` + `AddScopePolicy(...)` for any consuming microservice.
  - `AuthenticationService.TokenClientLib` — `AddServiceToken(audience, scopes)` for outgoing calls; cached, semaphore-protected, retry-on-`invalid_token`.
- **Three databases, one codebase** — MySQL, SQL Server, and PostgreSQL are all first-class. Pick via `DatabaseSettings:Provider`; each provider gets its own EF migrations assembly. CI runs the full integration suite against all three in parallel.
- **Admin surface** — user CRUD, invitation flow, client management, force-reset, audit endpoint, indefinite lockout. Gated by role + scope.
- **Security operations**:
  - Threshold-escalation worker warns and locks accounts on sustained revoked-token replay attempts (configurable warn / lock thresholds, idempotent).
  - Redis-backed rate limiting at both global and per-endpoint policy granularity.
  - Structured audit pipeline routing `SecurityEventIds`-tagged events to a persistent audit table + the standard log sink.
  - Data-protection key ring persisted to Redis with optional X.509 at-rest encryption.
- **OpenTelemetry** — traces, metrics, and logs wired throughout. A Grafana / Loki / Tempo / Prometheus stack is auto-provisioned when the AppHost runs locally; production wires up to any OTLP-compatible collector via `OTEL_EXPORTER_OTLP_ENDPOINT`.
- **Production-hardened** — Tier 0 audit closed (per-iteration safety in background workers, transient-error retry, validated settings with fail-fast startup, ProblemDetails error contract, signing-key backup runbook, custom DB health check, CSP without `unsafe-inline`).

## Documentation

Full documentation lives under [`docs/`](docs/) and is rendered by Backstage TechDocs in-platform. Start at [`docs/index.md`](docs/index.md) for the full nav.

## Quick links

| If you want to… | Go to |
|---|---|
| **Run it locally** (F5 → swagger) | [docs/getting-started.md](docs/getting-started.md) |
| **Understand the architecture** | [docs/architecture.md](docs/architecture.md) |
| **Wire a consumer to validate tokens** | [docs/consumers/validating-incoming-tokens.md](docs/consumers/validating-incoming-tokens.md) |
| **Make service-to-service calls** | [docs/consumers/outgoing-service-tokens.md](docs/consumers/outgoing-service-tokens.md) |
| **Deploy to production** | [docs/operations/deployment.md](docs/operations/deployment.md) |
| **Add / apply a database migration** | [docs/development/migrations.md](docs/development/migrations.md) |
| **Look up config keys** | [docs/reference/configuration.md](docs/reference/configuration.md) |
| **Look up an endpoint** | [docs/reference/endpoints.md](docs/reference/endpoints.md) |

## Contributing

See [docs/development/conventions.md](docs/development/conventions.md) for code style and [docs/development/adding-an-endpoint.md](docs/development/adding-an-endpoint.md) for a worked example of adding a new feature end-to-end.

## Status

Active findings are tracked in [`TODO.md`](TODO.md). Most items are "build when real demand arrives" — nothing on the list blocks adopting the service into a new microservice today.
