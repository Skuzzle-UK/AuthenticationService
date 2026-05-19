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

- [x] ~~**`RefreshToken.ReplacedByTokenId` populate fix.**~~ Rotation now stamps the
  back-pointer in the same race-protected UPDATE as `ConsumedAt`, in
  `JWTService.RotateRefreshTokenAsync`. Reuse-detection no longer needs to walk the
  chain via `CreatedAt` ordering.

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

- [x] ~~**Admin operational endpoints + Service-to-service auth flow.**~~ Both phases
  shipped:
  - **Phase 0** (admin endpoints): paginated user list / detail / lock / unlock /
    revoke-sessions / reset-MFA / force-password-reset / audit / admin-creates-user
    with invitation flow. Plus the `SecurityEventSink` audit pipeline. Plan doc:
    [`docs/admin-endpoints-plan.md`](docs/admin-endpoints-plan.md).
  - **Phase 1** (s2s auth): `Clients` + `ClientScopes` tables, `POST /oauth/token`
    client-credentials endpoint, service-JWT shape, admin client CRUD, OIDC discovery
    advertises `token_endpoint`, `AddScopePolicy` helper in
    `AuthenticationService.Client`, `ExampleConsumer` demo. Plan doc:
    [`docs/service-to-service-auth-plan.md`](docs/service-to-service-auth-plan.md).
  - **Phase 2** (optional hardening — JWT-bearer client assertions, mTLS, dynamic
    registration) deferred until real demand arrives.

- [ ] **No outgoing-token client helper for consuming services.**
  Phase 1 shipped the resource-server side (`AddScopePolicy`) but not the
  client side. Consuming services that want to call other services have to write
  their own token-fetch + cache + DelegatingHandler boilerplate. Standard .NET
  pattern; the absence forces every new consumer team to re-implement it (badly,
  five times across the platform).

  Plan ready: [`docs/service-token-client-plan.md`](docs/service-token-client-plan.md).
  ~half a day, scoped to `AuthenticationService.Client`. Adds `IServiceTokenProvider`,
  `ServiceTokenHandler`, `AddServiceToken(audience, scopes)` extension on
  `IHttpClientBuilder`. Settings file extends the existing options. End-state:
  ```csharp
  services.AddAuthenticationServiceTokenClient(config.GetSection("AuthenticationService"));
  services.AddHttpClient<InventoryClient>()
      .AddServiceToken("inventory-api", ["inventory.read"]);
  ```
  and the handler stamps the Bearer header on every outgoing call.

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

1. **Outgoing-token client helper** (~half day). Plan ready in
   [`docs/service-token-client-plan.md`](docs/service-token-client-plan.md). Small
   ergonomics win that closes the consumer-side gap left by Phase 1. Pick this up
   the moment a real consumer service is being wired in — the friction will be
   visible immediately.
2. **External IdP / SSO** — no plan yet. Wait until there's a concrete need (which
   provider, what claim mapping, what account-linking semantics).
3. **`OPERATIONS.md` runbook** — write when an actual ops person is about to join.
   Premature writing means the doc drifts before it's ever read.
4. **Pomelo migration** — blocked on Pomelo 10 release; re-check quarterly.

Phase 0 (admin endpoints), Phase 1 (s2s auth), Tier 4 observability, and the
data-integrity fixes are all shipped. The auth service has the observability, test
coverage (412 unit + 13 integration), CI workflow, audit pipeline, admin surface,
service-identity story, and consumer client lib of a production-grade microservice.
Remaining items are all "build when real demand arrives."
