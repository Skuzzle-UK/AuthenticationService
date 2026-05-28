# AuthenticationService

Centralised identity & access service for the platform. Issues short-lived ES256-signed JWTs and exposes a JWKS endpoint so consuming microservices can validate them without sharing secrets. Also issues service-identity JWTs via OAuth 2.0 client credentials for service-to-service calls.

## Where to start

| If you want to… | Read |
|---|---|
| Run it locally and try it out | [Getting started](getting-started.md) |
| Understand what's in this repo | [Architecture](architecture.md) |
| Wire your service to validate incoming tokens | [consumers/validating-incoming-tokens.md](consumers/validating-incoming-tokens.md) |
| Call another service from yours under a service identity | [consumers/outgoing-service-tokens.md](consumers/outgoing-service-tokens.md) |
| Deploy to production | [operations/deployment.md](operations/deployment.md) |
| Rotate the signing key | [operations/key-rotation.md](operations/key-rotation.md) |
| Read SIEM logs / metrics / traces | [operations/observability.md](operations/observability.md) |
| Look up a config value | [reference/configuration.md](reference/configuration.md) |
| Look up an endpoint | [reference/endpoints.md](reference/endpoints.md) |

## Conceptual docs

How things work, and why:

- [User auth flows](concepts/user-auth-flows.md) — register, log in, MFA, recovery
- [Refresh rotation & reuse cascade](concepts/refresh-rotation.md) — the theft-detection design
- [Service-to-service](concepts/service-to-service.md) — OAuth client credentials, scope model
- [Security model](concepts/security-model.md) — crypto, deny-list, rate limits, headers, audit pipeline

## For contributors

- [Testing](development/testing.md) — five test projects, 541 unit + 15 integration, zero skipped
- [Conventions](development/conventions.md) — comment style, naming, file organisation
- [Adding an endpoint](development/adding-an-endpoint.md) — recipe walking through the conventions in practice
- [Database migrations](development/migrations.md) — per-provider migration workflow (MySQL + SQL Server, Postgres planned)

## For operators

- [Deployment](operations/deployment.md)
- [Observability](operations/observability.md) (including SIEM contract)
- [Key rotation](operations/key-rotation.md) — routine + emergency rotation flow
- [Signing-key backup and restore](operations/signing-key-backup-and-restore.md) — secret-store-agnostic disaster-recovery runbook
- [Admin account recovery](operations/admin-recovery.md) — three break-glass paths if the seeded admin loses access
- [Runbook](operations/runbook.md) — decision tree + common procedures + "I can't log in" triage
- [Local Backstage via Aspire](operations/local-backstage.md) — catalog + TechDocs preview

## Reference

- [Configuration](reference/configuration.md) — every config key, default, and validator rule
- [Endpoints](reference/endpoints.md) — every HTTP route with auth requirement and purpose
- [Constants](reference/constants.md) — wire-contract values pinned by tests (claim names, security event IDs, policy names)

## Plan docs (settled history)

These captured the design decisions for the work that shipped. Kept around as ADR-style references — the design-rationale tables are the closest thing the codebase has to formal Architecture Decision Records.

- [Admin endpoints plan](admin-endpoints-plan.md) — Phase 0 shipped: admin user-management surface + invitation flow
- [Service-to-service auth plan](service-to-service-auth-plan.md) — Phase 1 shipped: OAuth client-credentials, scope model
- [Service-token client helper plan](service-token-client-plan.md) — consumer-side typed-client + 401-retry handler
