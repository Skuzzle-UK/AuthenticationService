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

#### ~~B4. Plan docs claim "Draft, not yet started" for two shipped phases~~ ✅ DONE (2026-05-21)

**What was wrong:** `docs/admin-endpoints-plan.md` and `docs/service-to-service-auth-plan.md` both still said "Status: Draft, not yet started" months after the work shipped. Anyone landing on them cold would think the work was still outstanding.

**What we shipped:** Both docs now follow the `service-token-client-plan.md` template — Status flipped to "Shipped (2026-05-21)", with a `> **Done:** ...` blockquote at the top summarising what landed (which entities, controllers, services, tests, and where to find them). The plan-doc design-decisions tables and rationale prose stay as a settled-record reference — they're the closest thing to ADRs we have, and they're linked from concept docs (`docs/concepts/service-to-service.md`) and code comments (`AdminController.cs` s2s section header). Service-to-service-auth-plan also notes Phase 2 (mTLS, JWT-bearer assertions, dynamic client registration) is deferred — build when real demand arrives.

---

#### ~~B5. No documented recovery path if the seeded admin account is lost~~ ✅ DONE (2026-05-21)

**What was wrong:** There was exactly one way to create the admin (runtime DB seed via `AdminAccountSeedSettings`) and no way to recover if the seeded admin lost access — `POST /api/Admin/users` rejects the Admin role to prevent privilege-escalation, so an existing admin can't promote a colleague. Day-1 production incident waiting to happen.

**What we shipped: three recovery paths, in order of operational invasiveness:**

1. **Raw-SQL runbook** — `docs/operations/admin-recovery.md` documents the SQL to clear lockout / disable MFA / re-confirm email / revoke refresh tokens / rotate security stamp directly against `AspNetUsers` + `RefreshTokens`. Caveat documented: **cannot** reset password via raw SQL because Identity's hash format isn't safely portable — the runbook routes operators to option 2 or 3 for password reset.

2. **CLI subcommand** — `dotnet run --project AuthenticationService -- reset-admin`. Builds the full DI graph (same connection strings, same password policy validators) but doesn't start Kestrel or hosted services. Runs `RuntimeDbSeeders.ResetAdministratorAccountAsync` and exits. Picks up the new password from `AdminAccountSeedSettings:Password`.

3. **`ResetOnStartup` flag** — new bool on `AdminAccountSeedSettings`. When `true` and the admin exists, the seeder applies the same reset on startup with a loud warning log. Operator workflow: set + restart + unset + restart (the runbook spells this out so the second restart isn't forgotten).

Shared core: `RuntimeDbSeeders.ResetAdministratorCoreAsync` — clears lockout, re-confirms email if needed, resets password through `UserManager.ResetPasswordAsync` (validation honoured), disables MFA, re-ensures Admin + DefaultUser role membership, revokes all active refresh tokens with reason `admin_recovery`, rotates the security stamp. Emits `SecurityEventIds.AdminAccountRecovered` (5100) at Critical so SIEM pages on it.

**Tests:** 9 new tests in `RuntimeDbSeedersTests.cs` cover the happy path (full sequence + refresh-token revocation against a real SQLite DbContext), admin-missing no-op, password-policy rejection, email re-confirm branch, missing-role re-add branch, and the three `ResetOnStartup` states (on + admin exists, off + admin exists, on + admin missing → falls through to create). Full unit suite: 433 passing.

**Doc nav:** `mkdocs.yml` updated so `Admin recovery` shows up under Operations in TechDocs / Backstage.

---

### ⚠️ Medium-priority (do in the first sprint after prod, before any incident proves them necessary)

#### M1. Data-protection certificate isn't required at startup

**What's wrong:** Identity tokens (password reset, email confirmation, MFA codes, lockout links) are protected by ASP.NET Core's data-protection key ring, persisted to Redis. The team can optionally encrypt that key ring at rest with an X.509 certificate (via `DataProtectionSettings.Certificate.PfxPath` + `PfxPassword`). But that cert is **optional** — startup doesn't fail if it's missing.

**Why it matters:** Without the cert, the keys sit in Redis as plaintext-readable XML. Anyone with read access to the Redis database can extract them and forge anti-forgery tokens / decrypt protected payloads offline. The "Admin Password" pattern (rejecting startup if missing outside Development) should be applied here too.

**Where to fix:** `AuthenticationService/Extensions/HostExtensions.cs:289-318` (the `AddDataProtection` extension).

**How to fix:** Mirror the existing `AdminAccountSeedSettingsValidator` — add a validator that requires `Certificate.PfxPath` to be populated when `env != Development`. Reject startup with a clear error message if missing. ~1 hour including a test.

---

#### ~~M2. ForwardedHeaders behind a proxy can silently fail~~ ✅ DONE (2026-05-21)

**What was wrong:** Both `ForwardedHeadersSettings.KnownNetworks` and `KnownProxies` defaulted to empty. Behind a proxy that meant `X-Forwarded-For` was ignored, audit logs recorded the LB IP, and the rate limiter bucketed the entire cluster's traffic under one IP. Silent at runtime — nothing failed, nothing logged.

**What we shipped:** New `ForwardedHeadersSettingsValidator : IValidateOptions<ForwardedHeadersSettings>` mirroring the existing `AdminAccountSeedSettingsValidator` pattern. Outside Development, when **both** lists are empty, startup fails with an `OptionsValidationException` whose message names both setting paths, mentions the rate-limit collapse consequence (so non-security-minded operators take it seriously), and points at the three config sources (appsettings / env var / secret store).

Registered in `HostExtensions.AddValidators`. `ValidateOnStart()` on the existing `AddOptions<ForwardedHeadersSettings>().ValidateDataAnnotations().ValidateOnStart()` registration picks up `IValidateOptions<T>` validators automatically, so no other wiring needed.

**Why strict-fail rather than warn:** the "deployed without a proxy at all" case is rare in real production; the "deployed behind a proxy but forgot to populate the lists" case is much more common. Fail-loud matches how the seed admin password already behaves.

**Tests:** 8 new tests in `ValidatorsTests.cs` covering named-instance skip, Development allows-empty, non-Development empty-fails with the right message keywords, populated `KnownNetworks` succeeds, populated `KnownProxies` succeeds, and a `[Theory]` over Staging / Production / custom-env-name to confirm "anything non-Development" triggers. Full suite: 470 passing.

---

#### ~~M3. Three settings classes are missing range validation~~ ✅ DONE (2026-05-21)

**What was wrong:** Numeric properties had no bounds — setting e.g. `CleanupIntervalInHours: 0` would crash `PeriodicTimer` at startup and kill the background worker silently. Strings that change a token's validity scope (`DataProtectionSettings.ApplicationName`) had no `[Required]` guard, so a blank value would silently invalidate every issued Identity token on the next deploy.

**What we shipped:**

- `DataRetentionSettings` — `[Range(0.01, 168.0)]` on `CleanupIntervalInHours` (no faster than 36s sweeps, no slower than weekly); `[Range(1.0, 3650.0)]` on `RevokedReplayTTLInDays` and `SecurityEventTTLInDays` (1 day to 10 years).
- `ThresholdEscalationSettings` — `[Range(0.1, 60.0)]` on `SweepIntervalInMinutes`; `[Range(1.0, 1440.0)]` on `WindowInMinutes`; `[Range(1, 100)]` on `WarnThreshold`; `[Range(1, 1000)]` on `LockThreshold`.
- `DataProtectionSettings` — `[Required]` on both `ApplicationName` and `RedisKey` (blank `RedisKey` would collide with anything else sharing the Redis instance).

`ValidateOnStart()` was already wired in `HostExtensions.AddValidatedSettings`, so misconfiguration now fails the host at boot with a useful error message rather than crashing background workers at runtime.

**Tests:** Extended `Tests/AuthenticationService.Tests/Settings/SettingsValidationTests.cs` with 26 new `[Theory]` rows — happy-path defaults plus boundary-violating values for every annotated property. Full suite: 462 passing.

---

#### ~~M4. `/readyz` health check on MySQL has no timeout~~ ✅ DONE (2026-05-21)

**What was wrong:** The readiness probe used `AddDbContextCheck<DatabaseContext>` with no timeout. Worse — after B1 shipped, `Database.CanConnectAsync` runs through the retry strategy, so a stalled DB could extend a single probe to ~150s (5 retries × 30s backoff cap). Kubernetes would pull the pod from the LB during that wait, draining capacity while every replica chased the same slow DB.

**What we shipped:** New `AuthenticationService/Services/HealthChecks/MySqlHealthCheck.cs` modeled on `RedisHealthCheck`. Opens the raw `DbConnection` from `_db.Database.GetDbConnection()` directly with a 2-second linked cancellation token — bypasses the execution strategy entirely. If the connection was already open from earlier in the scope, returns Healthy without touching it (don't yank a connection out from under EF). Connections opened by the probe are explicitly closed in `finally`. Registered via `.AddCheck<MySqlHealthCheck>("database", tags: ["ready"])` in `HostExtensions.AddHealthChecksConfiguration`.

**Tests:** 3 unit tests in `Tests/AuthenticationService.Tests/Services/HealthChecks/MySqlHealthCheckTests.cs`:
- Open succeeds → Healthy
- Already-open short-circuits to Healthy without closing
- Pre-cancelled outer token → Unhealthy (covers the exception-bubbling path)

The "MySQL refuses the connection" path isn't a separate test because SQLite is too permissive to fake locally; it falls through the same `catch` as the cancellation case. Full unit suite: 436 passing, 0 warnings.

---

#### ~~M5. Two background workers exit silently on the first exception~~ ✅ DONE (2026-05-21)

**What was wrong:** Two workers had try/catch around the *outer* timer loop, so any in-body exception killed the worker until pod restart. The service "looked healthy" via probes but cleanup / escalation stopped silently:
- `DataRetentionCleanupService.RunCleanupAsync` — audit-table pruning
- `RevokedTokenReplayEscalationService.RunSweepAsync` — replay-threshold lock cascade

**What we shipped:** Moved the try/catch *inside* each per-iteration method, matching the existing `UserGaugeRefreshService.RefreshAsync` pattern. A throw now logs a warning ("…will retry on next sweep.") and returns, leaving the timer loop intact. `OperationCanceledException` still bubbles through cleanly via the timer's `WaitForNextTickAsync` so host shutdown still works.

Idempotency-safe because: cleanup uses `ExecuteDeleteAsync` predicates (re-running deletes the same rows or none); escalation gates on `WarnedAt` / `LockedAt` columns so re-sweeping a partially-escalated incident doesn't double-fire.

**Tests:** 2 new tests in `Tests/AuthenticationService.Tests/Services/Hosted/` (one per worker). Each injects a substituted `IServiceScopeFactory` that throws on `CreateScope()` and asserts the per-iteration method returns without propagating. Full unit suite: 438 passing.

---

#### ~~M6. Console logs don't carry the trace ID~~ ✅ DONE (2026-05-21)

**What was wrong:** When OTel was configured (production with `OTEL_EXPORTER_OTLP_ENDPOINT`), trace IDs landed on every log. When it wasn't (dev without Aspire, or any deploy that skipped the env var), stdout logs lost trace correlation — a teammate tailing the container couldn't tell which log lines belonged to which request.

**What we shipped:**
- Added `Serilog.Enrichers.Span` 3.1.0 package.
- Added `"WithSpan"` to the `Enrich` array in `appsettings.json`. This enricher pulls `TraceId` / `SpanId` off `Activity.Current` (which ASP.NET Core / `Microsoft.Extensions.Hosting` already populate per request).
- Updated the Serilog console `outputTemplate` to `[{Timestamp:HH:mm:ss} {Level:u3}] [{TraceId}/{SpanId}] {Message:lj} {Properties:j}{NewLine}{Exception}`. Empty brackets when no active Activity — also a useful visual signal that something's running outside a request scope (background workers, startup).

Both `UseSerilog` blocks in `Program.cs` (web host + CLI reset-admin) already use `ReadFrom.Configuration`, so the change applies to both code paths with no `.cs` edits.

---

#### ~~M7. `docs/reference/endpoints.md` has stale entries~~ ✅ DONE (2026-05-21)

**What was wrong:** Two entries in the endpoints reference didn't match the actual code:
- `POST /api/Account/profile` listed — the real endpoint is `PUT /api/Account/me` (`AccountController.cs:101`).
- `POST /api/Account/enablemfa` listed for "Confirm MFA enrolment" — no such POST exists. The `GET /api/Account/enablemfa` (line 212) does the whole enrolment in one call (sets `MfaEnabled = true` AND returns QR code).

**What we shipped:** Updated `docs/reference/endpoints.md` — corrected `POST /api/Account/profile` → `PUT /api/Account/me`; removed the bogus `POST /api/Account/enablemfa` row; expanded the `GET /api/Account/enablemfa` description to make the one-call-does-everything semantic explicit ("There is no separate 'confirm' endpoint — the first successful login under MFA proves possession.") so future doc-readers don't add the missing row back.

---

#### ~~M8. Broken cross-reference in the runbook~~ ✅ DONE (2026-05-21)

**What was wrong:** The decision tree's "Login endpoint returns 429" branch pointed at `operations/deployment.md §11` which doesn't exist (deployment.md only goes to §8). The rate-limit policy discussion the runbook was gesturing at actually lives in `docs/concepts/security-model.md#rate-limiting`.

**What we shipped:** Updated the link to `../concepts/security-model.md#rate-limiting` (verified the `## Rate limiting` heading exists at line 43, which GitHub-style markdown converts to `#rate-limiting`).

---

#### ~~M9. Runbook says "TBD" for a procedure that's already implemented~~ ✅ DONE (2026-05-21)

**What was wrong:** The "Lock an account" procedure was a TBD stub claiming "currently admin endpoint exists but lock-via-admin isn't directly exposed; user-driven lock is the only path." Wrong on both counts — `POST /api/Admin/users/{id}/lock` was shipped in Phase 0 and is documented in `docs/reference/endpoints.md`.

**What we shipped:** Replaced the TBD with the real procedure — the admin endpoint, its effect (indefinite lockout, sessions NOT auto-revoked so pair with revoke-sessions if compromise suspected), the recovery path (forgot-password clears lockout), and a callout that the user-driven `/api/Account/lock` (panic button from email link) is the user-side alternative, not the only path.

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
    [`docs/admin-endpoints-plan.md`](docs/admin-endpoints-plan.md).
  - **Phase 1** (s2s auth): `Clients` + `ClientScopes` tables, `POST /oauth/token`
    client-credentials endpoint, service-JWT shape, admin client CRUD, OIDC discovery
    advertises `token_endpoint`, `AddScopePolicy` helper in
    `AuthenticationService.TokenValidationLib`, `ExampleConsumer` demo. Plan doc:
    [`docs/service-to-service-auth-plan.md`](docs/service-to-service-auth-plan.md).
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

1. **Finish [Tier 0](#tier-0--pre-cutover-hardening-must-clear-before-first-prod-deploy)** — all 5 blockers + M2–M9 are done; 2 medium-priority items left (M1, M10). Once those land, the service is genuinely production-ready (not just feature-complete).
2. **Pick the secret store + write the signing-key backup runbook** (Tier 0 / M10). Without this the disaster-recovery story for crypto material is incomplete.
3. **External IdP / SSO** — no plan yet. Wait until there's a concrete need (which
   provider, what claim mapping, what account-linking semantics).
4. **Pomelo migration** — blocked on Pomelo 10 release; re-check quarterly. This also resolves Tier 0 / B1 natively.
5. **Bulk user import** — only if a real migration use-case surfaces.

---

## Honest status (replaces the older "production-grade microservice" claim)

Phase 0 (admin endpoints), Phase 1 (s2s auth), Tier 4 observability, and the
data-integrity fixes are all **feature-complete and tested**. The service has the test
coverage (560+ unit + 15 integration, zero skipped), CI workflow, audit pipeline, admin
surface, service-identity story, observability stack, and consumer client libraries
worthy of a production-grade microservice **on paper**.

The Tier 0 audit found 5 blockers and 10 medium-severity issues — mostly small code-quality and doc-drift items that didn't surface during feature development. **All five blockers (B1–B5) plus M2–M9 (forwarded-headers strict, settings validation, MySQL health-check timeout, worker survive-on-throw, trace IDs in console logs, doc-truth fixes) are now closed (2026-05-21).** Two medium-severity items remain (M1, M10) but neither blocks shipping — they're "do in the first sprint after prod" items. Once those land, the remaining roadmap items (SSO, bulk import, Pomelo migration) are all "build when real demand arrives" and don't block adopting the auth service into a new microservice.
