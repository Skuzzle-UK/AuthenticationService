# Corporate-readiness TODO

Active findings only — closed items have been removed. Each entry carries the file/line so
it can be picked up cold. Tiered by impact for an enterprise, multi-replica, shared-by-many-apps
deployment; pick from the top and work down.

---

## Tier 1, 2 & 3 — closed

All items in these tiers are now done and have been removed. Covers multi-replica
correctness (refresh-token race, workers split, distributed rate limiter, queued email
send, etc.), the security-review-prep sweep (security headers, password length,
open-redirect fix, JWKS caching, etc.), and code-smell cleanup (`WaitingForMfa` /
`MothersMaidenName` dropped, profile-update endpoint built, AutoMapper removed,
`JwtSecurityTokenHandler` static, JWT expiry as `int`, request-body cap configurable).

---

## Tier 4 — Tests, observability, infrastructure

- [x] ~~**Unit tests landed.**~~ 396 tests across three test projects
  (`Tests/AuthenticationService.{Client,Shared,}.Tests`) using xUnit + AwesomeAssertions
  + NSubstitute. Every controller endpoint, every validator branch, full `JWTService`
  / `EcdsaKeyProvider` / middleware / helpers / hosted-services (sweep methods exposed
  via `InternalsVisibleTo`) coverage. Detailed coverage map in
  [`Tests/README.md`](Tests/README.md).

- [x] ~~**Integration tests landed.**~~ 8 scenario tests in
  `AuthenticationService.IntegrationTests/` driven by **.NET Aspire 13** (the AppHost
  project orchestrates real MySQL, Redis, and smtp4dev containers + the auth project as
  a normal process). Tests use `Aspire.Hosting.Testing` to boot the same graph
  programmatically and exercise the full stack end-to-end. Scenarios cover: registration
  → confirm → login, refresh-token rotation, refresh-token reuse cascade, password change
  → "wasn't me!" lock, rate-limiter integration, threshold-escalation worker, JWKS / OIDC
  consumer round-trip. **Three production-affecting bugs found in the process** —
  `DateOnly`/MySQL value-converter, `DateTimeOffset.MaxValue` DATETIME overflow,
  `Contains-on-collection` translation broken in Oracle's MySql.EntityFrameworkCore.
  Coverage map in [`AuthenticationService.IntegrationTests/README.md`](AuthenticationService.IntegrationTests/README.md).

- [x] ~~**CI workflow.**~~ GitHub Actions at `.github/workflows/ci.yml`. Two jobs:
  unit tests on every push (fast feedback), integration tests on PR + push-to-main
  (slower, runs against real MySQL / Redis / smtp4dev via Aspire). Runner is
  `ubuntu-latest` (Docker pre-installed). Status badge in README. Concurrency group
  cancels superseded runs to avoid queueing duplicate work on noisy push cycles.

- [ ] **`RefreshToken.ReplacedByTokenId` never populated** (found by Scenario 2 of the
  integration tests). The column exists on the entity for forensic chain-walking but
  the rotation logic only stamps `ConsumedAt` — without the back-pointer, reuse
  detection has to walk the chain via `CreatedAt` ordering rather than following an
  explicit link. Small fix, ~30 minutes — just set the field during rotation in
  `JWTService.RotateRefreshTokenAsync`.

- [ ] **Consider migrating from `MySql.EntityFrameworkCore` (Oracle) to `Pomelo.EntityFrameworkCore.MySql`** _(blocked: waiting on Pomelo 10 release)._
  All three integration-test bugs trace back to limitations in Oracle's provider that
  Pomelo handles natively:
  - `DateOnly` round-trip needs an explicit value converter against Oracle; Pomelo native.
  - `DateTimeOffset.MaxValue` overflows MySQL `DATETIME` via Oracle; Pomelo handles cleanly.
  - `Contains` on `List<string>` doesn't translate via Oracle (forced N+1 loop in
    threshold-escalation worker); Pomelo translates fine.

  **Status as of 2026-05-08:** the latest Pomelo on nuget.org is `9.0.0` which hard-pins
  to `Microsoft.EntityFrameworkCore.Relational 9.0.0–9.0.999`. The auth service is on
  EF Core 10. Downgrading EF Core to 9 across the .NET 10 stack would cascade into
  Identity / Aspire / hosting incompatibilities — not worth it.

  **Re-check quarterly.** Once Pomelo ships `10.0.0` (or any preview targeting
  EF Core 10), this migration becomes a half-day pass: swap the package, change
  `UseMySQL` → `UseMySql(connectionString, ServerVersion.AutoDetect(...))`, regenerate
  the migrations folder (the existing migrations reference Oracle-specific
  `MySql.EntityFrameworkCore.Metadata` types), revert the three workarounds, run tests.
  Migrations regeneration is the chunkiest piece — the existing schema is
  Oracle-flavoured DDL that Pomelo will recreate slightly differently (charset
  annotations, column types).

  **Workarounds in place until then:** `DateOnly` value converter in
  `DatabaseContext.OnModelCreating`, `LockoutDurations.Indefinite` sentinel constant,
  per-jti loop in `RevokedTokenReplayEscalationService.RunSweepAsync`. Each has a code
  comment explaining "this can revert when we move to Pomelo."

- [x] ~~**OpenTelemetry + custom business metrics.**~~ ServiceDefaults wires up
  ASP.NET Core / HttpClient / Runtime / EF Core instrumentation; `AuthMetrics` adds
  custom counters + gauges (login rate, MFA, refresh, reuse, lockouts, threshold
  escalation, total users, MFA adoption, active lockouts). Serilog OTLP sink routes
  logs to the same backend so trace ↔ log correlation works. AppHost spins up a
  `grafana/otel-lgtm` container with a pre-provisioned "Auth Service Overview"
  dashboard for dev. Production exports gated on `OTEL_EXPORTER_OTLP_ENDPOINT` env
  var. See README "Observability" section.

---

## Tier 5 — Missing features for enterprise multi-tenant use

These are likely real platform requirements once "shared by several apps" becomes more
than aspirational. None are blockers today; flagged so the design space is visible.

- [ ] **No admin operational endpoints + No service-to-service auth flow.**
  Combined work item — admin endpoints are a prerequisite for the DB-backed
  client-management surface that service-to-service auth needs.

  Two planning docs cover the design end-to-end:
  - [`docs/admin-endpoints-plan.md`](docs/admin-endpoints-plan.md) — Phase 0 detail
    (admin user-management endpoints + admin-creates-user invitation flow + basic page)
  - [`docs/service-to-service-auth-plan.md`](docs/service-to-service-auth-plan.md) —
    overall plan, Phase 1 (s2s auth) detail, Phase 2 hardening sketch

  Design decisions are settled; effort estimate is ~4 focused days split as:

  - **Phase 0** (~2 days) — Admin endpoint foundation:
    paginated user list / detail / lock-unlock / revoke-sessions / reset-MFA /
    force-password-reset / audit-trail + admin-creates-user with invitation email and
    a basic page where the new user sets their initial password. All gated by the
    existing `[Authorize(Policy = "AdminOnly")]`. Delivers the "admin operational
    endpoints" item independently. Adds Serilog SQL sink for the audit endpoint.

  - **Phase 1** (~2 days) — Service-to-service auth (DB-driven):
    `Clients` and `ClientScopes` tables, `POST /oauth/token` endpoint, service-identity
    JWT shape (sub = client_id, no user claims, scope claim), client library
    `AddScopePolicy` helper, `ExampleConsumer` demo, OIDC discovery update, integration
    scenarios 9 & 10. Reuses the admin endpoint surface from Phase 0 for client CRUD.

  - **Phase 2** — Optional hardening (JWT-bearer client assertions, mTLS, dynamic
    registration). Build when real demand arrives.

  Today's pain: consumers forward the user's JWT for service-to-service calls — audit
  logs blame the user not the calling service, and there's no story for cron jobs /
  message handlers / scheduled syncs that have no user in the call chain.

- [ ] **No external IdP integration (SSO).**
  Many corporate apps want "log in with Microsoft / Google / Entra ID." Not in scope
  today but a likely requirement once the platform matures. Design considerations: claim
  mapping, account linking (existing local + new SSO), lifecycle (what happens when SSO
  removes a user upstream).

- [ ] **No bulk user import.**
  Onboarding to a corporate platform with existing users elsewhere — there's no migration
  path. Not initial scope but flagged.

- [ ] **No backup / disaster-recovery story for signing keys.**
  The PEM keys in `PrivateKeyDirectory` *are* the contract. If they're lost, every issued
  token becomes invalid AND we can't issue new ones until new keys are provisioned AND
  cached JWKS at every consumer needs to refresh.
  **Fix:** Document the runbook — how to back up via the chosen secret-store mechanism,
  how to restore, how often to test restore, what to do if all replicas of all keys are
  lost simultaneously (full re-auth event for every user).

- [ ] **No `OPERATIONS.md` / runbook.**
  New ops person joining the team has nothing to read. Should cover: how to deploy, how
  to rotate keys, how to debug a user-reported lockout, how to read SIEM dashboards, how
  to issue an ad-hoc password reset for a user, how to interpret threshold-escalation
  events.

---

## Tier 6 — closed

All small corrections are now done: `RuntimeDbSeed` fails fast with a clear DB-unreachable
message, `WellKnownController.Jwks` returns a pre-built cached document, JWKS / discovery
endpoints have their own generous rate-limit partition. (Production config is
operator-overridden via env vars + the base `appsettings.json` — no separate Production
template needed.)

---

## Recommended next-up order

1. **Phase 0 — Admin endpoints** (~2 days). The next big work item. Plan ready in
   [`docs/admin-endpoints-plan.md`](docs/admin-endpoints-plan.md). Phase 1 (s2s auth)
   depends on it.
2. **Pomelo migration** — blocked on Pomelo 10 release; re-check quarterly.

The remaining Tier 4 work is all closed — the auth service has the observability,
test coverage, CI workflow, and data-integrity gates of a production-grade
microservice. Everything from here is feature work in Tier 5.
