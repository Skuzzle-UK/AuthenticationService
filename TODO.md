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

- [ ] **CI workflow not yet wired.**
  Both test suites run locally via `dotnet test` but there's no GitHub Actions / Azure
  Pipelines yaml. Minimum: a workflow that runs unit tests on every push (fast feedback,
  ~3s) and integration tests on PR + main (~60s, needs Docker on the runner).
  `ubuntu-latest` GitHub-Actions runners come with Docker pre-installed — half-day at
  most to wire up.

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

- [ ] **No OpenTelemetry / W3C trace propagation.**
  Auth is the most-logged-against service. Add `services.AddOpenTelemetry()` with
  ASP.NET Core + EF Core + HttpClient instrumentation; export to whatever the platform's
  collector is (OTLP). Pairs with the missing-metrics gap below — OTel covers both traces
  and metrics in the same package.

- [ ] **No metrics emitted.**
  Logs aren't metrics. For Prometheus / OTLP-style operational dashboards you want
  counters / histograms for login-success rate, MFA adoption, refresh frequency, lockout
  rate, threshold-escalation fires. Lights up automatically when OpenTelemetry lands —
  framework-level metrics for ASP.NET Core / EF Core / HttpClient are built in. Custom
  business-metrics (e.g. "MFA-enabled user count") would need explicit `Meter` / `Counter`
  calls.

---

## Tier 5 — Missing features for enterprise multi-tenant use

These are likely real platform requirements once "shared by several apps" becomes more
than aspirational. None are blockers today; flagged so the design space is visible.

- [ ] **No service-to-service auth flow (client-credentials grant).**
  Currently consumers forward the user's JWT for downstream calls. Wrong because (a)
  audit logs show the user not the calling service, (b) services need to call when no
  user is involved (cron jobs, message handlers).
  **Standard answer:** client-credentials flow — each service has a `client_id` /
  `client_secret`, exchanges them for a service-identity JWT with its own claims and
  audience. Multi-day piece of work.

- [ ] **No admin operational endpoints.**
  Operational must-haves for an enterprise auth service:
  - List users
  - View / modify user details
  - Manually lock / unlock specific user
  - Revoke a user's sessions
  - Reset their MFA
  - Force password reset
  - View audit trail for a specific user
  
  Currently none exist. Either build them as `[Authorize(Policy="AdminOnly")]` admin
  endpoints, or document that ops will go via direct DB access (acceptable but
  unprofessional for a corporate platform).

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

1. **CI workflow** — half-day. Smallest remaining gap before the test suite is fully
   automated. GitHub Actions yaml that runs unit tests on every push + integration tests
   on PR/main.
2. **`ReplacedByTokenId` populate fix** — 30 minutes. Closes the data-integrity gap
   found by Scenario 2.
3. **Pomelo migration** — half-day investigation. Removes the three workarounds the
   integration tests forced us to add. Drops them before they become magical-incantation
   tech debt.
4. **OpenTelemetry + metrics** — half-day, lights up dashboards. Pairs with CI since
   the workflow gives a place to assert metric shape doesn't regress.
5. **Tier 5** items as real platform requirements arrive — don't pre-build.

Rough effort estimate to reach "I'd put this in a production gate review with a straight
face": **a focused day or two for the remaining Tier 4 work.** Most of the heavy lifting
(unit + integration tests, the bugs they uncovered, the AppHost/ServiceDefaults pattern)
is now in place.
