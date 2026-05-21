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

## For operators

- [Deployment](operations/deployment.md)
- [Observability](operations/observability.md) (including SIEM contract)
- [Key rotation](operations/key-rotation.md) (including disaster recovery)
- [Runbook](operations/runbook.md) (skeleton, fills in as operationally exercised)
- [Local Backstage via Aspire](operations/local-backstage.md) (catalog + TechDocs preview)
