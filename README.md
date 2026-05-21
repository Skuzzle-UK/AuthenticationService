# AuthenticationService

[![CI](https://github.com/Skuzzle-UK/AuthenticationService/actions/workflows/ci.yml/badge.svg)](https://github.com/Skuzzle-UK/AuthenticationService/actions/workflows/ci.yml)

Centralised identity & access service for the platform. Issues short-lived ES256-signed JWTs (user + service-identity flavours), exposes a JWKS endpoint so consuming microservices can validate them without sharing secrets, and ships a pair of drop-in client libraries that handle both sides of the wire.

## Quick links

| If you want to… | Go to |
|---|---|
| **Run it locally** (F5 → swagger) | [docs/getting-started.md](docs/getting-started.md) |
| **Understand the architecture** | [docs/architecture.md](docs/architecture.md) |
| **Wire a consumer service to validate tokens** | [docs/consumers/validating-incoming-tokens.md](docs/consumers/validating-incoming-tokens.md) |
| **Make service-to-service calls** | [docs/consumers/outgoing-service-tokens.md](docs/consumers/outgoing-service-tokens.md) |
| **Deploy to production** | [docs/operations/deployment.md](docs/operations/deployment.md) |
| **Read SIEM logs / metrics / traces** | [docs/operations/observability.md](docs/operations/observability.md) |
| **Run / write tests** | [docs/development/testing.md](docs/development/testing.md) |
| **Look up config keys** | [docs/reference/configuration.md](docs/reference/configuration.md) |
| **Look up an endpoint** | [docs/reference/endpoints.md](docs/reference/endpoints.md) |
| **See the full nav** | [docs/index.md](docs/index.md) |

## What's in the repo

```
AuthenticationService/                       ← The HTTP API
AuthenticationService.Shared/                ← DTOs + wire-contract constants
AuthenticationService.TokenValidationLib/    ← Consumer lib: validate incoming JWTs
AuthenticationService.TokenClientLib/        ← Consumer lib: acquire outgoing tokens
AuthenticationService.ServiceDefaults/       ← OpenTelemetry + health-check defaults
AuthenticationService.AppHost/               ← Aspire orchestrator (dev/test only)
AuthenticationService.IntegrationTests/      ← E2E scenarios via Aspire.Hosting.Testing
ExampleConsumer/                             ← Demo consumer microservice
Tests/                                       ← Per-project xUnit suites
docs/                                        ← Audience-organised documentation
```

See [docs/architecture.md](docs/architecture.md) for the full breakdown.

## At a glance

- **541 unit tests** + **15 integration tests**, zero skipped, sub-minute on a developer laptop.
- **No shared secrets.** Consumers validate via JWKS — they never see the signing key.
- **ES256 only.** Restricted at validation time to defeat algorithm-confusion attacks.
- **OpenTelemetry traces / metrics / logs** wired throughout, with a Grafana stack auto-imported when the AppHost runs.
- **Production-deployed without Aspire.** Aspire is the dev front-end, not the runtime.
- **Backstage-ready.** TechDocs renders `docs/` directly; [`catalog-info.yaml`](catalog-info.yaml) declares the components.

## Contributing

See [docs/development/conventions.md](docs/development/conventions.md) for code style and [docs/development/adding-an-endpoint.md](docs/development/adding-an-endpoint.md) for a worked example.

## Status & roadmap

Active findings are in [`TODO.md`](TODO.md). Most items are "build when real demand arrives" — nothing on the list blocks adopting the service into a new microservice today.
