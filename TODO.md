# Corporate-readiness TODO

Active findings only — closed items have been removed. Each entry carries the file/line so
it can be picked up cold. Tiered by impact for an enterprise, multi-replica, shared-by-many-apps
deployment; pick from the top and work down.

> **For a new joiner:** start at [Tier 0](#tier-0--pre-cutover-hardening-must-clear-before-first-prod-deploy). Every item there explains what's wrong, why it matters, where to find it, and how to fix it. Once Tier 0 is clear, the service is genuinely production-ready.

---

## Tier 0 — Pre-cutover hardening (must clear before first prod deploy)

Findings from a production-readiness audit on 2026-05-21. These are mostly code-quality and doc-drift issues that didn't surface earlier because they're not missing features — they're small bugs or stale config that only show up under "is everything you committed to is actually true?" scrutiny.

Total estimated effort: ~1 dev-day if knocked out together. Order within the section is roughly impact-first.

### 🚨 Blockers (do before deploying to production)

#### ~~B1. Database connection retry policy is missing~~ ✅ DONE (2026-05-21)

**What was wrong:** When the auth service talked to MySQL and the connection hiccupped (deploy rollout, network blip, DB failover), the code gave up on the first failure instead of retrying. A MySQL flap could fail user requests AND silently kill background workers until the pod restarted.

**What we shipped:** Custom `MySqlRetryingExecutionStrategy` (`AuthenticationService/Storage/MySqlRetryingExecutionStrategy.cs`) that derives from EF Core's `ExecutionStrategy` base class and retries any exception that looks transient (`DbException`, `TimeoutException`, or anything whose type lives under the `MySqlConnector.` / `MySql.Data.` namespaces). Up to 5 retries with exponential backoff capped at 30s — base class handles jitter automatically. Wired into the `UseMySQL(...)` callback in `HostExtensions.AddDatabase` via `mysql.ExecutionStrategy(deps => new MySqlRetryingExecutionStrategy(deps))`.

**Why this approach (custom strategy vs. Pomelo migration):** Oracle's `MySql.EntityFrameworkCore` provider doesn't ship anything equivalent to Pomelo's `EnableRetryOnFailure`. We can't move to Pomelo yet — latest Pomelo on nuget is 9.0.0, which hard-pins EF Core 9. The custom strategy is well-isolated and uses only EF Core base classes, so it can be deleted in one commit when we eventually migrate to Pomelo 10 (see [Tier 4 Pomelo entry](#tier-4--tests-observability-infrastructure)). Pattern mirrors `RuntimeDbSeeders.IsTransientDatabaseError`.

**Tests:** 8 unit tests covering each transient/non-transient path in `Tests/AuthenticationService.Tests/Storage/MySqlRetryingExecutionStrategyTests.cs`. Verified the predicate, not the retry loop itself (base class is Microsoft's responsibility). Full unit suite: 423 passing, 0 warnings.

**Follow-on fix (2026-05-21):** when the retry strategy is registered, EF Core throws `InvalidOperationException: "The configured execution strategy 'MySqlRetryingExecutionStrategy' does not support user-initiated transactions..."` if code calls `BeginTransactionAsync()` directly. Wrapped both call sites in `db.Database.CreateExecutionStrategy().ExecuteAsync(...)` so the whole transaction is retried as one unit:
- `AuthenticationService/Controllers/RegistrationController.cs` — `RegisterUserAsync`
- `AuthenticationService/Services/JWTService.cs` — `RotateRefreshTokenAsync`

Caught by the `PasswordChange_WasntMeLink_LocksAccountAndSendsConfirmation` integration test failing with 500 on registration. Would have been caught earlier had B3 (CI gated on wrong branch) not silenced the integration job.

**Follow-up (not blocking):** integration test that drops MySQL mid-request and asserts the request retries + succeeds rather than 500s. Skipped for now because the harness can't easily simulate transient MySQL outages — left as a Tier 3 nice-to-have.

**Known edge case (not blocking):** `RegisterUserAsync` calls `SendConfirmEmailAsync` (in-memory channel queue) inside the retried block. If the final `CommitAsync` fails transiently, the retry will queue a second confirmation email. Pre-existing exposure; treat as a known minor under-load behaviour, not a correctness bug. Fix would mean moving the queue write outside the transaction — separate Tier 3 item if it ever surfaces.

---

#### ~~B2. Production exceptions return blank 500 responses (missing `/Error` endpoint)~~ ✅ DONE (2026-05-21)

**What was wrong:** The pipeline said "in production, when there's an unhandled error, render `/Error`" — but no such page existed. Any unhandled exception in production returned a blank 500 with no error code, no correlation ID, and no body. Operators investigating an alert had only the server-side log to work with.

**What we shipped:** Took the conventional ASP.NET Core 10 route — RFC 7807 ProblemDetails via the framework's built-in machinery.

- **`HostExtensions.AddProblemDetailsConfiguration()`** registers `AddProblemDetails(...)` with a `CustomizeProblemDetails` callback that always stamps `traceId` (preferring `Activity.Current?.Id`, falling back to `HttpContext.TraceIdentifier`). Wired into `ConfigureHost`.
- **`WebApplicationExtensions.ConfigureApplicationAsync`** now calls `app.UseExceptionHandler()` (parameterless — picks up the ProblemDetails service) in non-development environments, plus `app.UseStatusCodePages()` always (so empty 4xx responses also get a JSON body). The dead `"/Error"` route is gone.

Net result: any unhandled exception now returns `500 Application/problem+json` with `status`, `title`, and `traceId`. Empty 4xx responses (e.g. a 404 with no matching route) get the same treatment.

**Tests:** 2 focused tests in `Tests/AuthenticationService.Tests/Extensions/ProblemDetailsExceptionHandlerTests.cs` spin up a minimal `WebApplication` (via `Microsoft.AspNetCore.TestHost`) wired the same way as the real app:
- Unhandled exception → 500 + ProblemDetails JSON with non-empty `traceId`
- Unknown route → 404 + ProblemDetails JSON

Test project gained a `FrameworkReference` to `Microsoft.AspNetCore.App` and a `PackageReference` to `Microsoft.AspNetCore.TestHost`. Full unit suite: 425 passing, 0 warnings.

---

#### ~~B3. CI silently skips integration tests on push to `master`~~ ✅ DONE (2026-05-21)

**What was wrong:** The integration-tests job was gated on `github.ref == 'refs/heads/main'`, but the default branch is **`master`**. Every push to `master` silently skipped integration tests. The B1 follow-on bug (manual transactions inside the retry strategy throwing 500s) would have been caught earlier had this gate fired.

**What we shipped:**
- `.github/workflows/ci.yml:107` — gate changed from `refs/heads/main` → `refs/heads/master`.
- `.github/workflows/regen-openapi.yml:20` — same bug, fixed alongside. The OpenAPI auto-regen has never run since it was added; will now trigger on push to `master`.
- Stray "push to main" comments in both files updated for consistency. (`ci.yml:84`'s `main-results.trx` is a filename meaning "primary", not a branch — left alone.)

**Validation:** the next push to `master` will run the integration tests. If they pass, the gate works.

---

#### B4. Plan docs claim "Draft, not yet started" for two shipped phases

**What's wrong:** The two plan documents below still have **"Status: Draft, not yet started"** at the top, but the work they describe shipped weeks ago:
- `docs/admin-endpoints-plan.md` (line 3) — Phase 0 admin endpoints are live.
- `docs/service-to-service-auth-plan.md` (line 3) — Phase 1 OAuth client-credentials is live.

**Why it matters:** Anyone landing on these docs cold will think the work isn't done. They'll waste time re-checking, re-asking, or worse — re-doing.

**Where to fix:** Line 3 of each file.

**How to fix:** Change `**Status:** Draft, not yet started` to `**Status:** Shipped (<date>)`. Add a one-line "what landed" summary like the `service-token-client-plan.md` doc already has. ~10 min each.

---

#### B5. No documented recovery path if the seeded admin account is lost

**What's wrong:** There's exactly one way to create an admin account: the runtime DB seed (`AdminAccountSeedSettings`). The `POST /api/Admin/users` endpoint **explicitly rejects** requests that include the Admin role, so an existing admin can't promote a colleague. If the seeded admin loses access (forgotten password + lost MFA + locked email account), nobody can recover.

**Why it matters:** Day-1 production incident — someone fat-fingers MFA enrolment, loses their phone, and now no admin can perform admin tasks. There's no documented playbook for this scenario.

**Where to fix:** Add a new section in `docs/operations/runbook.md` (probably under "Common procedures"). Possibly also a small code change to allow controlled admin promotion through an existing-admin path.

**How to fix (doc-only path, ~30 min):** Write a "Admin account recovery" runbook section that walks the operator through direct DB intervention: connect via the prod MySQL credentials, run a SQL UPDATE to add the Admin role to a known user. Include the exact SQL and the audit-log entry that should follow.

**How to fix (code+doc path, half day):** Add a `POST /api/Admin/users/{id}/promote-to-admin` endpoint, gated on `[Authorize(Policy = AdminOnly)]` so an existing admin can do it. Block self-promotion (already a pattern in `AdminController`). Audit-log the action. Update the runbook to use this endpoint as the primary path, with the DB intervention as the "all admins are locked out" fallback.

---

### ⚠️ Medium-priority (do in the first sprint after prod, before any incident proves them necessary)

#### M1. Data-protection certificate isn't required at startup

**What's wrong:** Identity tokens (password reset, email confirmation, MFA codes, lockout links) are protected by ASP.NET Core's data-protection key ring, persisted to Redis. The team can optionally encrypt that key ring at rest with an X.509 certificate (via `DataProtectionSettings.Certificate.PfxPath` + `PfxPassword`). But that cert is **optional** — startup doesn't fail if it's missing.

**Why it matters:** Without the cert, the keys sit in Redis as plaintext-readable XML. Anyone with read access to the Redis database can extract them and forge anti-forgery tokens / decrypt protected payloads offline. The "Admin Password" pattern (rejecting startup if missing outside Development) should be applied here too.

**Where to fix:** `AuthenticationService/Extensions/HostExtensions.cs:289-318` (the `AddDataProtection` extension).

**How to fix:** Mirror the existing `AdminAccountSeedSettingsValidator` — add a validator that requires `Certificate.PfxPath` to be populated when `env != Development`. Reject startup with a clear error message if missing. ~1 hour including a test.

---

#### M2. ForwardedHeaders behind a proxy can silently fail

**What's wrong:** Behind a load balancer or reverse proxy, the service relies on `ForwardedHeadersSettings.KnownNetworks` (or `KnownProxies`) being populated so the `X-Forwarded-For` header is trusted. If those lists are empty, the middleware ignores the header and every request looks like it came from the LB itself.

**Why it matters:** Audit logs record the LB IP instead of the real client. Rate limiting partitions by LB IP, so a single bucket caps the entire cluster's traffic. Both consequences are silent — nothing fails, nothing logs an error.

**Where to fix:** `AuthenticationService/Extensions/HostExtensions.cs:340-358`.

**How to fix:** When the env is not Development AND both `KnownNetworks` and `KnownProxies` are empty, emit a startup warning (or, more conservatively, a startup error). Saves a real-world incident later. ~30 min.

---

#### M3. Three settings classes are missing range validation

**What's wrong:** Three settings classes have numeric properties without `[Range]` validation. If an operator sets one to `0` or a negative number, things crash at runtime instead of failing fast at startup.

- `Settings/DataRetentionSettings.cs` — `CleanupIntervalInHours`, `RevokedReplayTTLInDays`, `SecurityEventTTLInDays`
- `Settings/ThresholdEscalationSettings.cs` — `SweepIntervalInMinutes`, `WindowInMinutes`, `WarnThreshold`, `LockThreshold`
- `Settings/DataProtectionSettings.cs:20` — `ApplicationName` is also missing `[Required]` (silent change to it invalidates every outstanding Identity token).

**Why it matters:** Setting `CleanupIntervalInHours: 0` makes `PeriodicTimer` throw on construction, which kills the background worker. The service "comes up healthy" but cleanup never runs.

**Where to fix:** Add `[Range]` attributes to each numeric property, `[Required]` to `ApplicationName`. ~20 min total, plus a quick options-validation unit test for each (mirror the existing `*OptionsTests` pattern).

---

#### M4. `/readyz` health check on MySQL has no timeout

**What's wrong:** The readiness probe uses `AddDbContextCheck<DatabaseContext>` to verify MySQL is reachable. There's no per-check timeout, so if MySQL is stalled (rather than down), the probe hangs until framework defaults kick in (~30s).

**Why it matters:** Kubernetes treats a slow `/readyz` as "not ready yet" — the pod gets pulled from the LB while it tries to answer. If multiple pods are probing a slow MySQL simultaneously, you can briefly drain the cluster.

**Where to fix:** `AuthenticationService/Extensions/HostExtensions.cs:367`.

**How to fix:** Add a `TimeSpan` argument to `AddDbContextCheck(...)`. 2-3 seconds is plenty for a real connection. Match the existing pattern from `RedisHealthCheck.cs` which has a 1s timeout. ~15 min.

---

#### M5. Two background workers exit silently on the first exception

**What's wrong:** When a transient error happens (e.g. MySQL drops a connection), two of the background workers leave the loop and don't come back until the pod restarts:
- `Services/Hosted/DataRetentionCleanupService.cs:56-62` — the periodic cleanup that prunes expired audit rows.
- `Services/Hosted/RevokedTokenReplayEscalationService.cs:85-91` — the worker that escalates revoked-token replay attempts to warn/lock.

A third worker (`UserGaugeRefreshService`) does catch and continue (`:104-113`) — that's the pattern the other two should follow.

**Why it matters:** These workers are critical: cleanup keeps the audit table from growing forever, escalation locks accounts being hammered with revoked tokens. If they silently die, the service "looks healthy" via probes but security/cleanup behaviour stops working.

**Where to fix:** The two file paths above.

**How to fix:** Wrap the inner loop body with a try/catch that logs the exception and continues. Don't re-throw transients. Look at `UserGaugeRefreshService.cs:104-113` as the canonical pattern. ~30 min total.

---

#### M6. Console logs don't carry the trace ID

**What's wrong:** When the OpenTelemetry log exporter is configured (production), trace IDs land on every log entry and you can click from a span in Tempo/Jaeger straight to its logs. When OTel isn't configured (e.g. dev without Aspire, or any deploy that skips the OTLP env var), logs go only to stdout — and the stdout template doesn't include the trace/span IDs.

**Why it matters:** Stdout logs lose trace correlation. A teammate tailing the container's logs can't tell which log lines belong to which request without a separate join.

**Where to fix:** `appsettings.json:27` (the Serilog `outputTemplate`).

**How to fix:** Add `{TraceId}` and `{SpanId}` placeholders to the template, and ensure `.Enrich.WithSpan()` is in the Serilog config (or the equivalent OpenTelemetry trace-enricher). ~15 min.

---

#### M7. `docs/reference/endpoints.md` has stale entries

**What's wrong:** Two entries in the endpoints reference don't match the actual code:
- Line 29: lists `POST /api/Account/profile`, but the controller exposes `PUT /api/Account/me` (per `AccountController.cs:112` and the regenerated OpenAPI spec).
- Line 34: lists `POST /api/Account/enablemfa` for "Confirm MFA enrolment", but the controller only has `GET /api/Account/enablemfa` (`AccountController.cs:228`); enrolment confirmation is part of the GET response flow.

**Why it matters:** Anyone using this doc to integrate will write client code against endpoints that don't exist. Confusing, embarrassing, easy to fix.

**Where to fix:** `docs/reference/endpoints.md:29` and `:34`.

**How to fix:** Cross-check each entry against the corresponding controller action AND `docs/api/openapi.json`. Update the path, method, and summary to match. ~15 min.

---

#### M8. Broken cross-reference in the runbook

**What's wrong:** `docs/operations/runbook.md:31` references "`operations/deployment.md §11`", but the deployment doc only goes to §8. The content the runbook is gesturing at (rate-limit discussion) actually lives in `docs/concepts/security-model.md#rate-limiting`.

**Why it matters:** Broken links erode confidence in the docs. The person clicking the link is usually under pressure (incident response).

**Where to fix:** `docs/operations/runbook.md:31`.

**How to fix:** Update the link to point at `../concepts/security-model.md#rate-limiting`. ~5 min.

---

#### M9. Runbook says "TBD" for a procedure that's already implemented

**What's wrong:** `docs/operations/runbook.md:61` says:
> *"Lock an account — TBD — currently admin endpoint exists but lock-via-admin isn't directly exposed; user-driven lock (`/api/Account/lock`) is the only path."*

But `POST /api/Admin/users/{id}/lock` exists and is documented in `docs/reference/endpoints.md:47`.

**Why it matters:** Same as M7 — confidence erosion + missed capability. Someone needing this procedure will think it doesn't exist.

**Where to fix:** `docs/operations/runbook.md:61`.

**How to fix:** Replace the TBD with a one-paragraph "Use `POST /api/Admin/users/{id}/lock` as an admin. Effect: account locked indefinitely; recovery via forgot-password flow." ~10 min.

---

#### M10. Signing-key backup runbook is referenced but not written

**What's wrong:** `docs/operations/key-rotation.md`'s disaster-recovery section says "see the signing-key backup story" — but that story isn't written, it's deferred to a TODO entry. The key-rotation doc gives the impression the runbook exists.

**Why it matters:** Day-N production incident — all signing keys are lost. Operators reach for the runbook and find a placeholder. Worst possible moment to discover the doc isn't there.

**Where to fix:** Write `docs/operations/signing-key-backup-and-restore.md` (new file). Cross-link from `key-rotation.md`.

**How to fix:** This depends on which secret store the team picks (Key Vault, Secrets Manager, Vault, etc.). Each has different backup mechanisms. The doc needs to:
1. State which secret store the team uses for signing keys.
2. Document the backup mechanism (automatic? manual export? snapshot-based?).
3. State the restore procedure step-by-step.
4. State a restore-test cadence (e.g., "quarterly drill — restore from backup into a staging env and verify a token signed there validates against the prod JWKS").
5. State the runbook for "all keys lost" — accept that every issued token is now invalid; communicate to consumer-service teams; provision new keys; full re-auth event for every user.

Effort: half day, but **needs the secret-store decision first**. If the team hasn't picked one, that's the blocking step.

---

### 🛠 Nice-to-haves (eventual cleanups, no incident driving them)

These won't bite in production but are easy hygiene wins. Knock them out during a quiet half-day.

- **`User.FindFirst("sub")` magic string** in `AccountController.cs:413`. Every other controller uses `ClaimConstants.Sub`; this one was missed. Replace the literal with the constant. ~2 min.

- **`UserGaugeRefreshService` has no tests.** Its `internal RefreshAsync` is explicitly designed for unit-testing per its own XML doc, but no test file exists. Write 3 tests — happy path, DB throws (worker continues), cancellation. Pattern is identical to `DataRetentionCleanupServiceTests`. ~30 min.

- **Blanket `#pragma warning disable` in 6 settings/entities files** (`Entities/RevokedToken.cs:1`, `Entities/RevokedTokenAccessAttempt.cs:1`, `Settings/JWTSettings.cs:1`, `Settings/AdminAccountSeedSettings.cs:1`, `Settings/PublicUrlSettings.cs:1`, `Settings/EmailServerSettings.cs:1`). The real intent is `#pragma warning disable CS8618` (uninitialized non-nullable properties — the runtime initialiser handles them). Specifying the code prevents future legitimate warnings from being silently swallowed. ~20 min total.

- **No `<TreatWarningsAsErrors>` at the solution level.** Add a `Directory.Build.props` at the repo root with `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`. Build is clean today (0 warnings), but nothing currently prevents a future warning from being merged. ~10 min + verify the build still passes.

- **Dev-generated PEM file permissions.** `EcdsaKeyProvider.cs:101-103` writes auto-generated keys with the default umask (typically 0644 on Linux). Set 0600 explicitly via `File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite)`. Dev-only path, but trivial hardening. ~5 min.

- **CSP includes `'unsafe-inline'` for `script-src` and `style-src`** (`Middleware/SecurityHeadersMiddleware.cs:38-39`) because the Razor pages use inline JS. Move the three inline scripts (`ResetPassword.cshtml`, `AcceptInvitation.cshtml`, `LockAccount.cshtml`) to either separate files or nonce-based loading, then drop `'unsafe-inline'`. ~2 hours.

- **Dockerfile is missing a `HEALTHCHECK` directive.** Not required for K8s (it uses the `/livez` / `/readyz` probes), but breaks `docker run` smoke tests and Docker Desktop's UI status. Add `HEALTHCHECK CMD curl -f http://localhost:8080/livez || exit 1`. ~5 min.

- **`Dockerfile`'s pre-restore COPY** (`AuthenticationService/Dockerfile:15-17`) lists only `AuthenticationService` + `AuthenticationService.Shared`, missing `AuthenticationService.ServiceDefaults` even though the auth project references it. Build works (line 18 does `COPY . .`), but the restore-layer cache is invalidated on any non-csproj file change. Add the missing COPY line. ~3 min.

---

## Tier 4 — Tests, observability, infrastructure

- [x] ~~**Unit tests landed.**~~ 541 unit tests across four test projects
  (`Tests/AuthenticationService.{TokenValidationLib,TokenClientLib,Shared,}.Tests`) using
  xUnit + AwesomeAssertions + NSubstitute. Every controller endpoint, every validator
  branch, full `JWTService` / `EcdsaKeyProvider` / middleware / helpers / hosted-services
  (sweep methods exposed via `InternalsVisibleTo`) coverage, plus the outgoing-token
  provider's cache + refresh + discovery + retry contract and the handler's 401-retry path
  driven through an in-process `HttpMessageHandler` stub. Detailed coverage map in
  [`Tests/README.md`](Tests/README.md). *(One small coverage gap: see [Tier 0 nice-to-have](#-nice-to-haves-eventual-cleanups-no-incident-driving-them) re: UserGaugeRefreshService.)*

- [x] ~~**Integration tests landed.**~~ 15 scenario tests in
  `AuthenticationService.IntegrationTests/` driven by **.NET Aspire 13** (the AppHost
  project orchestrates real MySQL, Redis, and smtp4dev containers + the auth project as
  a normal process). Tests use `Aspire.Hosting.Testing` to boot the same graph
  programmatically and exercise the full stack end-to-end. Scenarios cover: registration
  → confirm → login, refresh-token rotation, refresh-token reuse cascade, password change
  → "wasn't me!" lock, rate-limiter integration, threshold-escalation worker, JWKS / OIDC
  consumer round-trip, admin invitation flow, admin force-password-reset, OAuth client-
  credentials happy path, OAuth scope authorisation, service-token client end-to-end.
  **Three production-affecting bugs found in the process** —
  `DateOnly`/MySQL value-converter, `DateTimeOffset.MaxValue` DATETIME overflow,
  `Contains-on-collection` translation broken in Oracle's MySql.EntityFrameworkCore.

- [x] ~~**CI workflow.**~~ GitHub Actions at `.github/workflows/ci.yml`. Two jobs:
  unit tests on every push (fast feedback), integration tests on PR + push-to-`master`
  (slower, runs against real MySQL / Redis / smtp4dev via Aspire). Runner is
  `ubuntu-latest`. Status badge in README. Concurrency group cancels superseded runs.

- [x] ~~**`RefreshToken.ReplacedByTokenId` populate fix.**~~ Rotation now stamps the
  back-pointer in the same race-protected UPDATE as `ConsumedAt`, in
  `JWTService.RotateRefreshTokenAsync`.

- [ ] **Consider migrating from `MySql.EntityFrameworkCore` (Oracle) to `Pomelo.EntityFrameworkCore.MySql`** _(blocked: waiting on Pomelo 10 release)._

  This is the long-term fix for [Tier 0 / B1](#b1-database-connection-retry-policy-is-missing). All three integration-test bugs noted above trace back to Oracle provider limitations that Pomelo handles natively:
  - `DateOnly` round-trip needs an explicit value converter against Oracle; Pomelo native.
  - `DateTimeOffset.MaxValue` overflows MySQL `DATETIME` via Oracle; Pomelo handles cleanly.
  - `Contains` on `List<string>` doesn't translate via Oracle (forced N+1 loop in
    threshold-escalation worker); Pomelo translates fine.

  **Status as of 2026-05-08:** latest Pomelo on nuget.org is `9.0.0`, which hard-pins to
  EF Core 9.0.x. We're on EF Core 10; downgrading would cascade into Identity / Aspire /
  hosting incompatibilities. Re-check quarterly; the migration is ~half a day once Pomelo 10 ships.

  **Workarounds in place until then:** `DateOnly` value converter in
  `DatabaseContext.OnModelCreating`, `LockoutDurations.Indefinite` sentinel constant,
  per-jti loop in `RevokedTokenReplayEscalationService.RunSweepAsync`. Each has a code
  comment explaining "this can revert when we move to Pomelo."

- [x] ~~**OpenTelemetry + custom business metrics.**~~ ServiceDefaults wires up
  ASP.NET Core / HttpClient / Runtime / EF Core instrumentation; `AuthMetrics` adds
  custom counters + gauges. Serilog OTLP sink routes logs to the same backend so trace ↔
  log correlation works *for OTLP-exported logs* (see [Tier 0 / M6](#m6-console-logs-dont-carry-the-trace-id) — console logs are missing the trace-ID fields). AppHost spins up a
  `grafana/otel-lgtm` container with a pre-provisioned "Auth Service Overview"
  dashboard for dev.

---

## Tier 5 — Missing features for enterprise multi-tenant use

These are likely real platform requirements once "shared by several apps" becomes more
than aspirational. None are blockers today; flagged so the design space is visible.

- [x] ~~**Admin operational endpoints + Service-to-service auth flow.**~~ Both phases
  shipped:
  - **Phase 0** (admin endpoints): paginated user list / detail / lock / unlock /
    revoke-sessions / reset-MFA / force-password-reset / audit / admin-creates-user
    with invitation flow. Plus the `SecurityEventSink` audit pipeline. Plan doc:
    [`docs/admin-endpoints-plan.md`](docs/admin-endpoints-plan.md). *(Plan doc still says "Draft" — see [Tier 0 / B4](#b4-plan-docs-claim-draft-not-yet-started-for-two-shipped-phases).)*
  - **Phase 1** (s2s auth): `Clients` + `ClientScopes` tables, `POST /oauth/token`
    client-credentials endpoint, service-JWT shape, admin client CRUD, OIDC discovery
    advertises `token_endpoint`, `AddScopePolicy` helper in
    `AuthenticationService.TokenValidationLib`, `ExampleConsumer` demo. Plan doc:
    [`docs/service-to-service-auth-plan.md`](docs/service-to-service-auth-plan.md). *(Plan doc still says "Draft" — see [Tier 0 / B4](#b4-plan-docs-claim-draft-not-yet-started-for-two-shipped-phases).)*
  - **Phase 2** (optional hardening — JWT-bearer client assertions, mTLS, dynamic
    registration) deferred until real demand arrives.

- [x] ~~**Outgoing-token client helper.**~~ Shipped as
  `AuthenticationService.TokenClientLib`. `IServiceTokenProvider` (singleton, cached, refresh-protected) +
  `ServiceTokenHandler` (`DelegatingHandler` with 401-invalidate-and-retry) + `AddAuthenticationServiceTokenClient` registration. 38 unit tests + 2 end-to-end integration tests. Plan doc:
  [`docs/service-token-client-plan.md`](docs/service-token-client-plan.md).

- [ ] **No external IdP integration (SSO).**
  Many corporate apps want "log in with Microsoft / Google / Entra ID." Not in scope
  today but a likely requirement once the platform matures. Design considerations: claim
  mapping, account linking (existing local + new SSO), lifecycle (what happens when SSO
  removes a user upstream).

- [ ] **No bulk user import.**
  Onboarding to a corporate platform with existing users elsewhere — there's no migration
  path. Not initial scope but flagged.

- [ ] **No backup / disaster-recovery story for signing keys.**
  Tracked in detail at [Tier 0 / M10](#m10-signing-key-backup-runbook-is-referenced-but-not-written) above — this Tier 5 entry was where it was originally surfaced; the Tier 0 entry has the concrete next-step framing.

- [ ] **No standalone `OPERATIONS.md` / consolidated runbook.**
  Partially addressed — `docs/operations/runbook.md` was scaffolded as a skeleton with explicit "TBD" markers for items needing first-hand operational experience. Three of those items have now surfaced as concrete Tier 0 entries (admin-account recovery [B5], stale procedure [M9], broken cross-ref [M8]). The remaining skeleton items in `runbook.md` (lines 90-97) are reasonable "fill in as the team actually operates the service" placeholders.

---

## Tier 6 — closed

All small corrections are now done: `RuntimeDbSeed` fails fast with a clear DB-unreachable
message, `WellKnownController.Jwks` returns a pre-built cached document, JWKS / discovery
endpoints have their own generous rate-limit partition. (Production config is
operator-overridden via env vars + the base `appsettings.json` — no separate Production
template needed.)

---

## Recommended next-up order

1. **Knock out [Tier 0](#tier-0--pre-cutover-hardening-must-clear-before-first-prod-deploy)** — ~1 dev-day for the 5 blockers + 10 medium-priority items. After this, the service is genuinely production-ready (not just feature-complete).
2. **Pick the secret store + write the signing-key backup runbook** (Tier 0 / M10). Without this the disaster-recovery story for crypto material is incomplete.
3. **External IdP / SSO** — no plan yet. Wait until there's a concrete need (which
   provider, what claim mapping, what account-linking semantics).
4. **Pomelo migration** — blocked on Pomelo 10 release; re-check quarterly. This also resolves Tier 0 / B1 natively.
5. **Bulk user import** — only if a real migration use-case surfaces.

---

## Honest status (replaces the older "production-grade microservice" claim)

Phase 0 (admin endpoints), Phase 1 (s2s auth), Tier 4 observability, and the
data-integrity fixes are all **feature-complete and tested**. The service has the test
coverage (541 unit + 15 integration, zero skipped), CI workflow, audit pipeline, admin
surface, service-identity story, observability stack, and consumer client libraries
worthy of a production-grade microservice **on paper**.

The Tier 0 audit found 5 blockers and 10 medium-severity issues — mostly small code-quality and doc-drift items that didn't surface during feature development. They total roughly 1 dev-day to clear. **B1 (DB retry policy), B2 (ProblemDetails), and B3 (CI branch gate) are now closed (2026-05-21).** **The service is not production-ready until the remaining Tier 0 items are closed.** Once they are, the remaining roadmap items (SSO, bulk import, Pomelo migration) are all "build when real demand arrives" and don't block adopting the auth service into a new microservice.
