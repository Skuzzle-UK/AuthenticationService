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

- [ ] **CI workflow not yet wired.**
  Tests run locally via `dotnet test` but there's no GitHub Actions / Azure Pipelines
  yaml. Minimum: a workflow that runs `dotnet build` + `dotnet test` on PR.

- [ ] **Integration tests via Testcontainers.**
  Unit tests use SQLite InMemory + substituted `IUserService` / `ITokenService`. An
  end-to-end auth flow against a real MySQL container would catch EF query shapes
  that diverge between SQLite and MySQL (collation, JSON columns, etc.). Pairs with
  fake-SMTP container (e.g. MailHog) for the `QueuedEmailService` consumer loop —
  currently only the producer side is unit-tested.

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

1. **Tier 4 item 1: tests + CI.** The single biggest open piece. Multi-day.
   Surface is now stable enough — Tier 1 + 2 + 3 + 6 settled, Tier 5 is individually
   feature-shaped and won't reshape what tests target.
2. **Tier 4 items 2-3 (OpenTelemetry + metrics)** — half-day, lights up dashboards.
   Pairs with item 1 since CI gives a place to assert metrics shape doesn't regress.
3. **Tier 5** items as real platform requirements arrive — don't pre-build.

Rough effort estimate to reach "I'd put this in a production gate review with a straight
face": **tests + CI is the gating piece.** Maybe a week of focused work; less if you're
happy with unit-test-only coverage rather than full integration tests via Testcontainers.
