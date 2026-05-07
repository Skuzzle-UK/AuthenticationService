# Corporate-readiness TODO

Active findings only — closed items have been removed. Each entry carries the file/line so
it can be picked up cold. Tiered by impact for an enterprise, multi-replica, shared-by-many-apps
deployment; pick from the top and work down.

---

## Tier 1 — Correctness and multi-replica blockers

These are real bugs or operational issues that will manifest under load with multiple
replicas. Highest leverage for "production gate review with a straight face."


- [ ] **Background workers run on every replica.**
  Both `DataRetentionCleanupService` and `RevokedTokenReplayEscalationService` are
  registered via `AddHostedService` so they run on every API replica. Two replicas can
  cross the threshold for the same `jti` simultaneously and both fire warn/lock — the
  nullable-column idempotency depends on a read-modify-write that has its own race here.
  Cleanup also runs N× concurrently every 12h.
  **Fix options:**
  - Move workers to a separate K8s Deployment with `replicas=1` (cleanest — same image,
    different startup mode, e.g. a `--workers-only` flag).
  - Leader election via a Redis-based distributed lock (we already have the multiplexer).
  - EF concurrency tokens on `WarnedAt`/`LockedAt` — doesn't stop duplicate work but stops
    duplicate writes.



- [ ] **Rate limiter is per-replica (in-memory).**
  [HostExtensions.AddRateLimiting](AuthenticationService/Extensions/HostExtensions.cs:376).
  `PartitionedRateLimiter.Create<...>` is in-memory. With 3 replicas, the actual cap is 3×
  the configured value because each replica counts independently. Credential stuffing
  through the LB sees 3× the throughput.
  **Fix options:**
  - Distributed rate limiter via Redis (e.g. `cristipufu/aspnetcore-redis-rate-limiting`
    NuGet) — uses the multiplexer we already have.
  - Push credential-stuffing protection up the stack (Azure Front Door, AWS WAF,
    Cloudflare).
  - Accept the multiplier and tighten thresholds by replica count (fragile).

- [ ] **Email sending blocks the request thread.**
  Every `_emailService.SendEmailAsync` call in controllers happens inline. Slow SMTP →
  slow login response. SMTP timeout → 500 to the user.
  **Fix:** Background task queue. Either build a small `Channel<T>` with a worker, pull in
  a NuGet (Hangfire/MassTransit/Coravel) if the platform allows, or at minimum set tight
  `SmtpClient.Timeout` so failures fail fast.

---

## Tier 2 — Security review prep

Things a corporate-security review would flag. Individually small, collectively the
difference between "polished" and "rough."

- [ ] **Swagger UI always exposed in production.**
  [WebApplicationExtensions.ConfigureApplicationAsync:37-41](AuthenticationService/Extensions/WebApplicationExtensions.cs:37).
  `UseSwagger()` and `UseSwaggerUI()` run unconditionally. Production deploys leak the
  entire API surface to anyone who can hit the service.
  **Fix:** Gate behind `app.Environment.IsDevelopment()`, or behind admin-only auth, or
  restrict by IP at the LB. JSON `swagger.json` can stay if internal services consume it.

- [ ] **No security response headers.**
  Pipeline-wide. HSTS is on (good) but missing `Content-Security-Policy`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`,
  `Permissions-Policy`. For an auth service these are tickbox items in any corporate
  review.
  **Fix:** Add `NetEscapades.AspNetCore.SecurityHeaders` (well-maintained, fluent config),
  or hand-rolled middleware.

- [ ] **`EmailServerSettings.Password = "Pa5$word123"` in `appsettings.json`.**
  [appsettings.json:88](AuthenticationService/appsettings.json:88). Same problem we fixed
  for `AdminAccountSeedSettings.Password`. Strip from `appsettings.json`, put dev value in
  `appsettings.Development.json`, optionally validate non-Dev presence.

- [ ] **Password length minimum is 8.**
  [HostExtensions.AddSecurity:150](AuthenticationService/Extensions/HostExtensions.cs:150).
  `Password.RequiredLength = 8`. NIST 800-63B and OWASP both recommend min 12 for user
  passwords. 8 was the standard a decade ago; modern audits flag it.
  **Fix:** Bump to 12. Optional: integrate HaveIBeenPwned via a small HTTP client (free
  k-anonymity API, no plaintext password leaves your service) — modern guidance is anti-
  complexity-rules and pro-blocklist.

- [ ] **`ConfirmEmailAsync` callback is an open-redirect.**
  [RegistrationController.ConfirmEmailAsync](AuthenticationService/Controllers/RegistrationController.cs).
  `return Redirect(callbackUri)` where `callbackUri` came from a query parameter. An
  attacker can craft a registration confirmation link with `callbackUri=https://evil.com/phish`
  — the link's domain is the auth service (looks legit), but it lands the user on a
  phishing page after confirmation.
  **Fix:** Validate `callbackUri` against an allow-list (perhaps reuse
  `CorsSettings.AllowedOrigins`, or introduce a `RecoveryRedirectAllowedOrigins`), or
  restrict to relative URLs only.

- [ ] **JWKS / OIDC discovery has no `Cache-Control`.**
  [WellKnownController](AuthenticationService/Controllers/WellKnownController.cs). JWKS is
  hit by every consuming microservice at startup. With many consumers, no caching headers
  means every consumer round-trips on every restart. JwtBearer caches client-side anyway,
  but corporate proxies / CDNs can't cache without explicit headers.
  **Fix:** `[ResponseCache(Duration = 3600, Location = ResponseCacheLocation.Any)]` (or
  set `Cache-Control: public, max-age=3600` headers manually).

- [ ] **`OpenIdConfiguration.jwks_uri` still uses request-derived URL.**
  [WellKnownController.cs:58](AuthenticationService/Controllers/WellKnownController.cs:58).
  We unified email-link URLs onto `PublicUrlSettings.BaseUrl` but missed this one. Behind
  a reverse proxy not preserving Host, the discovery doc would advertise the internal LB
  hostname.
  **Fix:** Use `_publicUrlSettings.BaseUrl` here too.

- [ ] **Razor pages embed model values via `@Model.X` inside JS.**
  [Pages/ResetPassword.cshtml](AuthenticationService/Pages/ResetPassword.cshtml),
  [Pages/LockAccount.cshtml](AuthenticationService/Pages/LockAccount.cshtml). `'@Model.Token'`
  and `'@Model.Email'` inside JavaScript. Razor's HtmlEncoder defaults *happen* to be safe
  in script-tag context (HTML entities don't decode inside `<script>`), but the principled
  approach is `@Json.Serialize(Model.Token)` which produces a properly JS-encoded value
  regardless of context.
  **Fix:** Replace with `@Json.Serialize(...)`.

---

## Tier 3 — Code smells and known gaps

- [ ] **`User.WaitingForMfa` is a persisted boolean.**
  [User.cs:20](AuthenticationService/Entities/User.cs:20). Storing "is this user
  mid-MFA-challenge" on the User entity is the wrong shape — it's *session* state, not
  user state. Two browsers starting MFA simultaneously can't both succeed; the flag
  persists across replica restarts even when no challenge is outstanding.
  **Fix:** Drop it. Replace with a short-lived signed cookie / state token, or derive
  "in MFA" from a fresh-issued MFA token in Identity's `UserToken` store.

- [ ] **Residual fields on `User` entity.**
  [User.cs:25-40](AuthenticationService/Entities/User.cs:25). `MothersMaidenName`,
  `AddressLine1-3`, `Postcode`, `City` exist with no flow using them — leftovers from the
  deleted recovery flow. Plus the `// TODO: Update user details endpoint /nb` in
  AccountController hints at intent.
  **Fix:** Either build a profile-update endpoint that uses them, or drop the fields and
  add a column-drop migration. One or the other; current state is worst-of-both.

- [ ] **`JwtSecurityTokenHandler` instantiated per call.**
  [JWTService.cs](AuthenticationService/Services/JWTService.cs) — multiple sites.
  `new JwtSecurityTokenHandler()` created on every token operation. Lightweight but
  unnecessary allocation.
  **Fix:** `private static readonly JwtSecurityTokenHandler _handler = new();`. Thread-safe
  for the operations we use.

- [ ] **`EmailSubjects` has three near-identical lock subjects.**
  [EmailSubjects.cs:9-11](AuthenticationService/Constants/EmailSubjects.cs:9). `AccountLocked`
  is unused; `LockedAccountInfo` is for failed-login lockout; `SuspiciousActivity` is for
  refresh-reuse + threshold-escalation. Either rationalise to two (or one) or document
  the distinction.

- [ ] **`JWTSettings.ExpiryInMinutes` is `double`.**
  [JWTSettings.cs](AuthenticationService/Settings/JWTSettings.cs). `double` reads as
  "fractional minutes are meaningful" which they aren't. Either `int` (conventional) or
  `TimeSpan` (clearest). Cosmetic.

- [ ] **`AddAutoMapper(cfg => { }, typeof(Program))`.**
  [HostExtensions.cs:35](AuthenticationService/Extensions/HostExtensions.cs:35). Empty
  config delegate is a smell. If `RegistrationDto → User` is the only mapping (worth
  checking), hand-rolling is clearer and faster. AutoMapper's own current guidance is
  "use it where you have many mappings; hand-roll for one or two."

- [ ] **No HTTP request size limit.**
  Kestrel default is 30 MB. For an auth service that takes only small JSON bodies, this
  is overkill and a small DoS surface.
  **Fix:** Configure `KestrelServerOptions.Limits.MaxRequestBodySize` to something sane
  (1 MB).

---

## Tier 4 — Tests, observability, infrastructure

- [ ] **No tests, no CI.**
  No `*Test*.csproj`, no GitHub Actions / Azure Pipelines yaml. At minimum:
  - Unit tests for `JWTService` (claim shape, expiry, validation, rotation, reuse
    detection), `EcdsaKeyProvider`, the validators, the threshold-escalation worker logic.
  - Integration tests for the auth flow against a real MySQL container (Testcontainers).
  - Snapshot test for the JWKS / OIDC discovery doc shape.
  - CI workflow that runs `dotnet build` + tests on PR.

  Best done after Tier 1 lands so tests target a stable, correctness-improved surface.

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

## Tier 6 — Small corrections

- [ ] **`RuntimeDbSeed` doesn't handle DB unavailable at startup gracefully.** Would
  crash the replica with an opaque error. Either retry-with-backoff, or log clearly and
  fail fast so K8s reschedules.

- [ ] **`WellKnownController.Jwks` allocates new anonymous objects on every call.** Could
  be cached on `IEcdsaKeyProvider` since keys don't change at runtime (or invalidate on
  the next loader refresh, which doesn't currently exist anyway).


- [ ] **No `appsettings.Production.json` template.** Operators have nothing to copy/paste
  from. A template with placeholder values + comments explaining what each setting needs
  in production would shorten the bootstrap.

- [ ] **JWKS / discovery endpoints share the global rate-limit partition.** During a key
  rotation, many consumers fetching JWKS through the same outbound IP (corporate NAT)
  could trip the 4/10s default. Worth a more generous policy on `/.well-known/*`.

---

## Recommended next-up order

1. **Tier 1 items 1-5** (~1-2 days) — real correctness / multi-replica issues. Highest
   leverage. Refresh-token race fix is probably the single highest-value item.
2. **Tier 1 item 6** (email queueing, ~half-day) — operationally important under load.
3. **Tier 2 items 1, 3** (Swagger gating, SMTP password — ~1 hour) — small but
   visible-to-security wins.
4. **Tier 4 item 1: tests + CI.** Now you're testing a stable, correctness-improved
   surface — coverage you write during/after Tier 1 catches the regressions you'd
   otherwise re-introduce.
5. **Tier 4 items 2-3 (OpenTelemetry + metrics)** — half-day, lights up dashboards.
6. **Remaining Tier 2** as you go — individually small.
7. **Tier 5** items as real platform requirements arrive — don't pre-build.
8. **Tier 3 + 6** opportunistically alongside the above.

Rough effort estimate to reach "I'd put this in a production gate review with a straight
face": ~2 weeks of focused work for Tiers 1+2+4, plus whatever piece of Tier 5 arrives.
