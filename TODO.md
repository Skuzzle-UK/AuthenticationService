# Corporate-readiness TODO

Findings from the project review on 2026-04-30. Ordered by category; recommended fix order
is at the bottom. Each item carries the file/line where the issue lives so it can be picked
up cold.

---

## Security correctness (bugs / vulnerabilities)

- [x] ~~**`ChangePassword` doesn't bind identity from the bearer token.**
  [AccountController.cs:193-231](AuthenticationService/Controllers/AccountController.cs:193) reads
  `request.Email` from the body and looks the user up by that. A logged-in user A can change
  user B's password if they know B's email + B's old password. The user must be derived from
  `User.Identity.Name` (or the `sub`/`jti` claim), and the request body's email must either be
  removed or asserted equal.~~ Done — identity now derives from the `sub` claim via
  `FindByIdAsync(User.FindFirst("sub")?.Value)`; `Email` removed from `ChangePasswordDto`;
  added the missing lockout check (closing the silent-unlock side-effect); email subject/body
  now correctly say "changed" not "reset".

- [x] ~~**Account-recovery static-PII bypass.**
  [UserService.VerifyRecoverAccountValues](AuthenticationService/Services/UserService.cs:107)
  treats every nullable field as `(stored is null || stored == supplied)`, so any field a user
  left blank at registration is unverified. Practical recovery secret reduces to
  email + username + DOB. Replace with email-link recovery: generate a single-use token, email
  it, validate on submission, rotate the security stamp on consumption. Rate-limit per
  email/IP and add a per-user lockout independent of the login lockout.~~ Done — recover
  endpoint deleted entirely; the password-reset flow is now the unlock path. Lockout checks
  removed from `ForgotPasswordAsync`/`ResetForgottenPasswordAsync`; `LockAccountAsync` now
  emails a real reset link so users can self-recover from a malicious password change in one
  click. (Per-email rate limiting still pending under the rate-limiter entry below.)

- [x] ~~**DTO/entity name mismatch silently drops mother's-maiden-name.**
  [RegistrationDto.MothersMaidenName](AuthenticationService.Shared/Dtos/RegistrationDto.cs:40)
  vs [User.MotherMaidenName](AuthenticationService/Entities/User.cs:29). AutoMapper convention
  doesn't match. Compounds the recovery bypass above. Fix: rename one side or add an explicit
  AutoMapper mapping; backfill is unnecessary because the column is currently always null.~~
  Done — entity field renamed to `MothersMaidenName` so AutoMapper convention matches.
  (Now moot anyway since the recovery endpoint that consumed it is gone.)

- [x] ~~**`JWTService.AddAccessAttemptAsync` semantics are inverted.**
  [JWTService.cs:103-124](AuthenticationService/Services/JWTService.cs:103). If the token's
  `jti` is *not* in the revoked table, the method calls `RevokeTokenAsync(...)` on it. Today
  it's only invoked from `RevokedTokenMiddleware` inside an `if (IsRevoked)` block so the
  inverted branch is unreachable, but a future caller will silently revoke valid tokens.
  Either rename to `RecordRevokedAccessAttemptAsync` and remove the auto-revoke branch, or
  split the method into two with explicit names.~~ Done — method renamed to
  `RecordAccessAttemptAsync`, inverted branch removed entirely; now writes a single
  `AccessRecord` with a calculated `Severity` (Medium for live-revoked replays, Low for
  past-expiry replays). `RevokeTokenAsync` no longer writes an `AccessRecord` itself —
  middleware handles that on replay, no double-counting. New `Severity` enum + entity column
  + migration shipped together.

- [x] ~~**`Logout` is `[HttpGet]` and not `[Authorize]`.**
  [AuthenticationController.cs:184-197](AuthenticationService/Controllers/AuthenticationController.cs:184).
  State-changing on GET (link-prefetch / image-tag CSRF). With no Authorize attribute, missing
  bearer header throws inside `ReadJwtToken("")` and returns 500 instead of 401. Change to
  `[HttpPost]` + `[Authorize]`, derive the token from `HttpContext.GetTokenAsync("access_token")`
  rather than re-parsing the header.~~ Done — `[HttpPost]` + `[Authorize]`, identity derived
  from the validated principal via `User.FindFirst(ClaimConstants.Sub)`, missing-user case
  returns 200 (logout is idempotent), and the inline 401 message uses the new
  `ErrorMessageConstants.InvalidToken`. Side win: the constants reorg moved all wire-contract
  values (`ClaimConstants`, `RolesConstants`, `PolicyConstants`, `AuthSchemeConstants`) into
  `AuthenticationService.Shared.Constants`, so the auth service no longer takes a project
  reference on the consumer SDK.

- [x] ~~**Refresh tokens stored in plaintext.**
  [User.cs:24](AuthenticationService/Entities/User.cs:24). Hash before persisting (SHA-256 of
  the random bytes is fine — they're high-entropy). On `/refresh`, hash the supplied token
  and compare.~~ Done — refresh tokens now stored as SHA-256 hashes in a dedicated
  `RefreshTokens` table; the raw token only ever exists in transit. The old
  `User.RefreshToken`/`RefreshTokenExpiresAt` columns were dropped in migration
  `DropRefreshTokenColumnsFromUser`.

- [x] ~~**Refresh-token rotation-on-use + reuse detection.**
  When a refresh token is presented at [AuthenticationController.RefreshTokenAsync](AuthenticationService/Controllers/AuthenticationController.cs:149),
  issue a new refresh token and *immediately* invalidate the presented one. If the same
  refresh token is later presented again, treat it as theft: revoke the entire token family
  (clear `RefreshToken` and rotate the security stamp via `InvalidateUserTokensAsync`),
  force re-login, and emit a high-severity security event so the user can be alerted.~~ Done
  — `JWTService.RotateRefreshTokenAsync` is the OAuth2 rotation-with-reuse-detection
  pattern. Each refresh consumes the presented token and issues a new one in the same
  family (new `sid` claim threads the family across rotations). Reuse detection fires the
  defensive cascade: revoke every refresh-token family for the user + rotate the security
  stamp + email the user about suspicious activity + emit a `LogWarning` security event.
  Per-device logout (`/logout`) revokes just the caller's family; `/logout-all` is a new
  endpoint for the everywhere-out case. Cleanup service sweeps expired refresh-token rows
  alongside revoked tokens.

- [x] ~~**No threshold escalation on revoked-token replay.**
  Today [RevokedTokenMiddleware](AuthenticationService/Middleware/RevokedTokenMiddleware.cs)
  401s and writes an `AccessRecord` row when a revoked token is replayed, but nothing
  escalates if the same `jti` is hammered against the API many times (a stolen-token replay
  by automation). Add a hosted service that periodically scans `AccessRecords` for the same
  `jti` from the same `UserId`:
  - At ~3 attempts within ~10 minutes: emit a security event.
  - At ~10 attempts: lock the account via `_userManager.SetLockoutEndDateAsync` and email
    the user a "your old token is being replayed, change your password" notice.
  Cheap to implement on top of the audit data already being collected (no new tables, no
  new endpoints — just a periodic query and a hosted worker). Pairs naturally with the
  cleanup service that already exists in
  [Services/Hosted](AuthenticationService/Services/Hosted/RevokedTokenCleanupService.cs).~~
  Done — `RevokedTokenReplayEscalationService` background worker scans
  `RevokedTokenAccessAttempts` every minute, evaluates two thresholds in a sliding window
  (defaults: warn at 2 replays in 5 min, lock at 5 in 5 min — tighter than the original
  TODO suggested because legitimate retry-on-old-token traffic is bursty, not sustained).
  Idempotency via two new nullable columns on `RevokedToken` (`WarnedAt`, `LockedAt`) so
  each escalation level fires once per incident. Lock cascade matches the refresh-token
  reuse pattern: `LockoutEnd = MaxValue`, revoke every refresh-token family, rotate the
  security stamp, email the user with a ready-made reset link built from the new
  `PublicUrlSettings:BaseUrl` (required outside Dev, dev default in
  `appsettings.Development.json`). Two new SIEM event IDs in the 4000s range — 4004
  Warning, 4005 Critical. README has a dedicated §9a section explaining the worker plus
  config reference and SIEM detection rule.

- [x] ~~**Behavioural anomaly detection on token use (defer to SIEM, do not build inline).**
  Real-world token-theft detection looks for: same `jti` used from geographically impossible
  IPs within minutes (impossible travel), sudden user-agent change, token used from an IP
  block on a known-bad list, etc. This is product territory — Auth0 / Okta / Entra Identity
  Protection sell it as a feature, and the rules need ongoing maintenance against evolving
  attacker behaviour. For a corporate deployment, the right path is to forward the
  structured security events emitted by the threshold escalator above to the platform's
  existing SIEM / fraud-detection team and let their rules engine handle it. Flagged here
  so we don't reinvent it; **the implementation work is "wire up a log sink", not "build
  detection."**~~ Closed as a deliberate non-feature. The auth service emits the structured
  security-event taxonomy that a SIEM / fraud-detection team needs to write rules against;
  detection itself is the SIEM team's domain because it requires continuously-updated
  threat intel feeds, geo-IP databases, and per-user behavioural baselines that don't fit
  inside an auth service. To strengthen the SIEM hand-off, added `UserAgent` enrichment via
  `HttpContextLogEnricher` so behavioural rules ("user's UA shifted from Chrome to curl")
  have the data they need without code changes per event. Deployment-time work to actually
  wire logs to a SIEM (Splunk HEC, Sentinel, OTLP, etc.) is in the operator's hands; the
  README field-shape contract documents what the SIEM will see.

- [x] ~~**No reuse defence on Identity-issued links (`ConfirmEmail`).**
  `LockAccount`, `ChangePassword`, and `ResetForgottenPassword` all call
  `InvalidateUserTokensAsync` post-consumption (rotates the security stamp, so the issuing
  link can't be replayed). `ConfirmEmailAsync` in [RegistrationController](AuthenticationService/Controllers/RegistrationController.cs:91)
  doesn't — `_userManager.ConfirmEmailAsync` flips `EmailConfirmed = true` but doesn't rotate
  the stamp.~~ Done — `IUserService` exposes a `UpdateSecurityStampAsync` passthrough;
  `RegistrationController.ConfirmEmailAsync` calls it after the successful confirm. Brings
  the email-confirm path into line with every other Identity-token consumption path.

- [x] ~~**Reserved-username registration not blocked.**
  [RegistrationDto.cs:8](AuthenticationService.Shared/Dtos/RegistrationDto.cs:8) has no deny
  list. Add a check (case-insensitive) for `admin`, `administrator`, `root`, `system`,
  `support`, `security`, `null`, etc. before `CreateAsync`.~~ Done — `Constants/ReservedUserNames.cs`
  holds the deny-list; `Validators/ReservedUserNameValidator.cs` is registered as an
  `IUserValidator<User>` via `AddUserValidator<...>` in `HostExtensions.AddSecurity`. Runs
  automatically inside `UserManager.CreateAsync` (and any future `UpdateAsync` if a username
  rename endpoint lands), returns an `IdentityResult` failure that flows through the
  existing controller error path. `"admin"` is deliberately not in the list because the
  seeded admin already holds that username — Identity's uniqueness constraint protects it
  for now; add it when `RuntimeDbSeeders` goes away (separate TODO).

- [x] ~~**`RegistrationController` returns `ex.Message` on 500.**
  [RegistrationController.cs:78](AuthenticationService/Controllers/RegistrationController.cs:78).
  Leaks DB / framework details. Log the exception with a correlation id, return a generic
  500 with that id.~~ Done — exception now logged via `_logger.LogError` with a fresh
  correlation Guid; response is a generic `ApiResponse` carrying the correlation ID for
  support to look up, no `ex.Message` exposed.

- [x] ~~**Default admin password shipped in `appsettings.json`.**
  [appsettings.json:13](AuthenticationService/appsettings.json:13) — `Pa5$word123`. Remove
  the default and require `AdminAccountSeedSettings:Password` to be supplied via env var /
  user-secrets / vault. Fail startup if it's still the placeholder.~~ Done — `Password`
  removed from `appsettings.json`; the dev-only default lives in `appsettings.Development.json`
  so `dotnet run` still Just Works for devs. New `Validators/AdminAccountSeedSettingsValidator`
  (registered as `IValidateOptions<AdminAccountSeedSettings>`) rejects the dev default in
  non-Development environments at startup — operators must supply a real value via env var /
  user-secrets / secret store. README's quick-start and production-deployment sections updated
  with the override mechanism + the explicit "REQUIRED outside Development" note.

---

## Operational correctness (will break in multi-replica prod)

- [x] ~~**Persist data-protection keys.**
  ASP.NET Core's data-protection ring defaults to ephemeral container storage. Every Identity
  token (email confirmation, password reset, lockout, MFA) is signed with this ring. In
  multi-replica deploys, tokens minted by replica A won't validate on B; on restart, every
  outstanding email link breaks.~~ Done — `HostExtensions.AddDataProtectionConfiguration`
  persists the key ring to Redis (using `ConnectionStrings:Redis`) in non-Development
  environments; startup fails fast if Redis isn't configured outside Dev. Application name
  pins the key isolation. `DataProtectionSettings.Certificate` is the config slot for adding
  `ProtectKeysWithCertificate` later — pure-config change, no code touch when the platform
  cert story is ready. Caveat: until the cert is configured, Redis-stored keys sit as
  readable XML — acceptable behind a controlled network during initial rollout, but the
  cert should land before the service is exposed broadly. Also requires Redis to have AOF/RDB
  persistence configured; without it, a Redis restart wipes the key ring and breaks every
  in-flight email-link token.

- [x] ~~**`UseForwardedHeaders` is missing.**
  Behind any LB / reverse proxy, `Connection.RemoteIpAddress` is the proxy. Audit IPs and
  the rate-limiter's IP partition will all be wrong.~~ Done — `UseForwardedHeaders` is the
  first piece of middleware in the pipeline, configured from `ForwardedHeadersSettings`
  (`KnownNetworks` CIDRs + `KnownProxies` IPs). Honours `X-Forwarded-For` and
  `X-Forwarded-Proto` from explicitly-trusted upstreams only; `X-Forwarded-Host` is
  intentionally not honoured (host-header attack surface). Implicit framework default of
  trusting loopback proxies is cleared — trust is explicit-only. With trust lists empty
  it's a no-op (single-host / local-dev). Once the platform team populates the LB subnet,
  every audit IP and the rate-limiter partition automatically become real client IPs
  without any further code change.

- [x] ~~**No health-check endpoints.**
  Add `services.AddHealthChecks()` with DB + JWT-key-loadable probes; map `/healthz` (live)
  and `/readyz` (ready, includes DB).~~ Done — `/healthz` (liveness, no dependencies) and
  `/readyz` (readiness, checks DB via `AddDbContextCheck` + Redis via custom
  `RedisHealthCheck` that shares the existing `IConnectionMultiplexer`). Both anonymous;
  rate-limited via a path-based partition in the global limiter (30 req/10s per IP for
  health endpoints, the regular 4 req/10s elsewhere) so orchestrator probes don't get
  throttled but DDoS abuse is still capped. Signing-key check skipped — startup fail-fast
  already catches that case before health checks matter.

- [x] ~~**Migrations run unconditionally at startup.**
  [WebApplicationExtensions.RunMigrations](AuthenticationService/Extensions/WebApplicationExtensions.cs:45-54).
  Multi-replica startup races. Move migrations to a separate `dotnet ef database update`
  step in the deploy pipeline (or an init-container / Job in K8s), and gate the runtime call
  behind an env flag for local-dev only.~~ Done — `RunMigrationsAtStartup` config flag
  (default `true`) gates the call. Dev keeps the "just works" startup-migrate behaviour;
  production deploys set the flag to `false` and run `dotnet ef database update` from the
  deploy pipeline. When skipped, the app logs an info message so it's clear the no-migrate
  path was deliberate, not a bug. README's production-deployment section documents the
  rationale and the pipeline expectation.

- [x] ~~**CORS is not configured.**
  Browser-based clients can't call this. Add `services.AddCors(...)` with an explicit
  origin allow-list bound from configuration; apply the policy via `app.UseCors(...)` between
  `UseRouting` and `UseAuthentication`.~~ Done — `CorsSettings.AllowedOrigins` drives an
  explicit allow-list (empty = no cross-origin access; fail-closed). Methods pinned to
  `GET/POST/OPTIONS`, headers to `Authorization/Content-Type/Accept`, `AllowCredentials`
  off (JWT in header, not cookies). `app.UseCors()` placed before `UseAuthentication` so
  preflight OPTIONS isn't auth-challenged. `appsettings.Development.json` carries
  permissive defaults for common dev frontend ports (3000, 4200, 5173); production
  `appsettings.json` ships with empty list — explicit override required.

- [x] ~~**Structured logging / security events are absent.**
  Two `_logger` calls in the entire codebase. Wire Serilog (or whatever the platform
  standard is) and emit structured events for: registration, registration-confirmed,
  login-success, login-failure, lockout-triggered, password-reset-requested,
  password-reset-completed, password-changed, refresh-issued, logout, token-revoked,
  recovery-attempt, MFA-enabled, MFA-failed. Tag with `userId`, `jti`, `ip`, `userAgent`.
  Pipe to whatever SIEM the corporate platform uses.~~ Done — Serilog wired up with the
  two-stage init pattern in `Program.Main`; `UseSerilogRequestLogging` filters health-check
  noise to Verbose. `Constants/SecurityEventIds.cs` defines the 20-event taxonomy across
  four EventId ranges (1000s auth, 2000s registration, 3000s account, 4000s token). Inline
  `_logger.LogX(SecurityEventIds.X, "Message {UserId} {IpAddress} ...", ...)` calls at every
  flow point — login (success/failure with reason), MFA (challenge/verified/failed),
  refresh (rotated/reuse-detected at Critical), logout (per-device/all), password
  (changed/reset-requested/reset-completed), MFA enabled, account locked by user, email
  confirmation success/failure, token revoked, revoked-token replay. Field shape is
  consistent across events (`UserId`, `IpAddress`, `Jti`, `FamilyId`, `Reason`, `Severity`).
  PII control: `UserId` (the `sub` claim) is logged for forensic correlation; email
  addresses are not in event payloads.

- [x] ~~**Single signing key, no rotation.**
  [EcdsaKeyProvider](AuthenticationService/Services/EcdsaKeyProvider.cs) holds one key; the
  JWKS endpoint exposes one. Add `IReadOnlyList<EcdsaKey>` keys, with one designated as
  active for signing; publish all of them in the JWKS response so consumers can validate
  during overlap windows. Add a runbook for rotation: introduce new key, wait one
  cache-refresh cycle, switch active, wait until the longest-lived old token expires, drop
  the old key.~~ Done — `EcdsaKeyProvider` now scans `JWTSettings:PrivateKeyDirectory` for
  every `*.pem` file and holds them all in memory. `ActiveKeyId` config picks the signer
  (`"auto"` = first key found, deterministic during single-key operation; explicit thumbprint
  during rotation cutover). JwtBearer validation and `JWTService.ValidateExpiredTokenAsync`
  use `IssuerSigningKeys` (plural) so tokens signed by any loaded key still validate during
  the overlap window. The JWKS endpoint enumerates every loaded key. Dev convenience preserved:
  empty directory in Development auto-generates a single PEM on first run; outside Development
  startup fails fast if the directory is empty (operator-provisioned only). Operator runbook
  is in README under "Key rotation".

- [ ] **No tests, no CI.**
  No `*Test*.csproj`, no GitHub Actions / Azure Pipelines yaml. At minimum:
  - Unit tests for `JWTService` (claim shape, expiry, validation) and the password validator.
  - Integration tests for the auth flow against a real MySQL container (Testcontainers).
  - Snapshot test for the JWKS / OIDC discovery doc shape.
  - CI workflow that runs `dotnet build` + tests on PR.

- [ ] **No OpenTelemetry / W3C trace propagation.**
  Auth is the most-logged-against service. Add `services.AddOpenTelemetry()` with
  ASP.NET Core + EF Core + HttpClient instrumentation; export to whatever the platform's
  collector is (OTLP).

---

## Standards / interop

- [x] ~~**`OpenIdConfiguration` advertises capabilities the service doesn't have.**
  [WellKnownController.cs:65](AuthenticationService/Controllers/WellKnownController.cs:65)
  declares `response_types_supported = ["token"]` without an `/authorize` or `/token`
  endpoint. Either implement OAuth2 / OIDC properly (preferred long-term — switch to
  Duende IdentityServer or OpenIddict) or trim the discovery doc to the minimum JwtBearer
  needs (`issuer`, `jwks_uri`, `id_token_signing_alg_values_supported`).~~ Done — trimmed to
  the three fields JwtBearer actually consumes. `response_types_supported` and
  `subject_types_supported` removed. If a full OIDC surface is needed in future, switch to
  Duende IdentityServer or OpenIddict rather than re-extending this doc.

- [x] ~~**`kid` is not the RFC 7638 JWK thumbprint.**
  [EcdsaKeyProvider.ComputeThumbprint](AuthenticationService/Services/EcdsaKeyProvider.cs:89)
  computes `SHA256(X || Y)`. Replace with the canonical-JSON form: `SHA256(`
  `{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}` `)` with members in lexical order.~~ Done
  — `LoadedKey.FromPemFile` now builds the JWK first then derives `kid` via
  `JsonWebKey.ComputeJwkThumbprint()` (the framework's RFC 7638 implementation), avoiding any
  hand-rolled canonicalisation. The bespoke `ComputeThumbprint` helper is gone. **Note:** this
  changes the `kid` value emitted for every key, so any existing dev keys produce a new `kid`
  on next startup. Operators with `JWTSettings:ActiveKeyId` pinned to an explicit thumbprint
  must recompute and update it; `"auto"` callers are unaffected.

- [x] ~~**Issued JWTs lack `sub`.**
  [JWTService.GetClaims](AuthenticationService/Services/JWTService.cs:199-213) emits only
  `jti`, `name`, and roles. Add `JwtRegisteredClaimNames.Sub = user.Id` and
  `JwtRegisteredClaimNames.Email = user.Email` so consumers don't have to round-trip a
  username (which can change) to get a stable identifier.~~ Done — token now emits
  `sub`/`name`/`email`/`role`/`jti`; server + client both run with `MapInboundClaims = false`
  + explicit `NameClaimType`/`RoleClaimType`; rate limiter and all controller lookups switched
  to ID-based via `FindByIdAsync(GetUserId(...))`; legacy `GetUserName` / `FindByNameAsync`
  abstractions removed.

- [x] ~~**`Authority` vs `Issuer` discrepancy is a footgun.**
  In dev, `Authority = https://localhost:53217` but `Issuer = https://auth.example.com`.
  README explains it, but a corporate deploy should make these match by terminating TLS at
  a reverse proxy with the canonical hostname. Document the production network expectation
  alongside the README's "HTTPS / hostname" section.~~ Done — README §8 now has an
  "`Authority` and `Issuer` — make them match in production" subsection that frames the
  two as routing-target vs logical-name, explains why they diverge in dev (no reverse proxy)
  and converge in prod, names the specific failure mode (`IDX10205: Issuer validation
  failed`) so an operator googling that error lands here, and tells deployments to
  terminate TLS at a proxy with the canonical hostname matching `JWTSettings.ValidIssuer`.
  The consumer-wiring chapter's existing callout box reworded to cross-reference §8 and
  make the "set both explicitly" rationale concrete.

---

## Smaller corrections worth bundling

- [x] ~~Sync-over-async in
  [RuntimeDbSeeders](AuthenticationService/Storage/Seed/RuntimeDbSeeders.cs:25) (`.Result`,
  `.Wait()`). Make `SeedAdministratorAccount` async and `await` the calls from
  `RuntimeDbSeed` (which can be made `async Task` and awaited at startup).~~ Done — full
  async chain: `Main` → `ConfigureApplicationAsync` → `RuntimeDbSeedAsync` →
  `SeedAdministratorAccountAsync`. Every `.Result` and `.Wait()` replaced with `await`.
  Methods that return `Task` now carry the conventional `Async` suffix. `app.Run()` swapped
  for `await app.RunAsync()` to keep the chain awaitable through to process exit.
  `RunMigrations` left sync — `dbContext.Database.Migrate()` is genuinely synchronous, not
  sync-over-async.

- [x] ~~**`Token` class has four constructor overloads** for the same fields
  ([Token.cs](AuthenticationService.Shared/Models/Token.cs)). Collapse to one constructor or
  use an init-only record with required members.~~ Done — converted to init-only properties
  with `required` on `Type` and `Value`. Construction is now via object initializer at the
  one call site in `JWTService`, which makes the field names visible at the call site and
  removes the positional-order risk. Stayed a `class` rather than going to `record` to
  avoid record's auto-generated `ToString()` printing the JWT into any log it ends up in.

- [x] ~~**`AccessRecord.Revoked` is hardcoded `true`.**
  [JWTService.cs:89,119](AuthenticationService/Services/JWTService.cs:89). Either capture
  every access (not just revoked-token attempts) or drop the column and rename the table to
  `RevokedTokenAccessAttempts`.~~ Done — went with the rename + column-drop path. Entity
  `AccessRecord` → `RevokedTokenAccessAttempt`; `DbSet` and table renamed; non-destructive
  EF migration `RenameAccessRecordsToRevokedTokenAccessAttempts` ships the rename + column
  drop without losing existing rows. While in there, killed the redundant DB lookup:
  `ITokenService.IsRevokedAsync` (returned bool) replaced by `GetRevokedTokenAsync`
  (returns `RevokedToken?`); the middleware now loads the row once and passes it to
  `RecordRevokedReplayAsync`, so the recording path no longer re-queries `RevokedTokens`.
  Also renamed the related setting `AccessRecordsTTLInDays` → `RevokedReplayTTLInDays` for
  consistency (both `appsettings.json` and `DataRetentionSettings`).

- [x] ~~**Rate-limiter is one global partition.**
  [HostExtensions.AddRateLimiting](AuthenticationService/Extensions/HostExtensions.cs:167) —
  4 req / 10s. Tighten on `/authenticate`, `/forgotpassword`, `/forgotpassword/reset`, `/mfa`,
  and `/lock`; relax on `/me`-style reads. Use named policies +
  `[EnableRateLimiting("auth-strict")]` per endpoint. (`/forgotpassword` is now also the
  unlock path post-merge, so the per-email partition matters more than it used to.)~~ Done
  — two named policies in `Constants/RateLimitPolicies.cs` registered alongside the global
  default. `AuthStrict` (10/min per IP) tags `authenticate`, `mfa`, `forgotpassword`,
  `forgotpassword/reset`, `lock`, `register`, `confirm/email` (resend) — credential-stuffing
  defense at the per-IP layer that doesn't rely on the user being authenticated. `AuthSensitive`
  (10/min per user) tags `changepassword` and `enablemfa` — tighter than the global default
  for authenticated state-changing endpoints. Global limiter (4/10s) still applies to
  everything as a backstop; named policies stack on top, most-restrictive wins. Health
  endpoints unchanged at their permissive 30/10s. `/refresh`, `/logout`, `/logoutall` left on
  global default — frequent legitimate use, the per-user 4/10s is fine.

- [x] ~~**`LockoutEnd = UtcNow.AddYears(100)`** in
  [AccountController.LockAccountAsync](AuthenticationService/Controllers/AccountController.cs:255).
  Replace with `DateTimeOffset.MaxValue` or a separate `IsHardLocked` flag — far-future
  arithmetic risks `DateTime` overflow on quirky host clocks.~~ Done — using
  `DateTimeOffset.MaxValue`.

- [x] ~~**Phone MFA is half-built.**
  [AuthenticationController.cs:84](AuthenticationService/Controllers/AuthenticationController.cs:84)
  and [AccountController.cs:84](AuthenticationService/Controllers/AccountController.cs:84)
  return BadRequest "PhoneMfaNotSupported". Either implement (SMS provider integration) or
  remove the enum value so it can't be selected.~~ Done — landed the wiring stub:
  `ISmsService` interface + `NotConfiguredSmsService` default registration in
  `HostExtensions.AddServices`. The Phone case in both controllers (`AuthenticateAsync`,
  `EnableMfaAsync`) checks `_smsService.IsConfigured` and `user.PhoneNumberConfirmed`
  before sending; failures return clear `PhoneMfaNotConfigured` / `PhoneNumberNotConfirmed`
  errors. Identity's built-in `TokenOptions.DefaultPhoneProvider` handles token gen/verify.
  When a real provider arrives (Twilio, AWS SNS, etc.), implementing `ISmsService` and
  swapping the registration is a one-line change — controllers don't move. README's "Open
  items" notes that a phone-number confirmation flow (mirror of email confirmation) also
  needs building before phone MFA is end-to-end usable.

- [x] ~~**No `/me` introspection endpoint.**
  Useful for consumers debugging "is the token I have actually any good?". Add
  `GET /api/Account/me` returning the resolved `User` snapshot (without sensitive fields)
  for the bearer.~~ Done — `GET /api/Account/me` returns a live `MeResponse` (id, username,
  email + confirmation flag, name, DOB, address, country, MFA state, roles). Identity comes
  from the token's `sub` claim. Orphan-token defence rolled out across every Bearer endpoint
  that looks up the user from the token (`MeAsync`, `EnableMfaAsync`, `ChangePasswordAsync`,
  `LogoutAllAsync`): if the user is gone, revoke the access token via the new
  `ITokenService.RevokeOrphanedTokenAsync` helper — which calls `RevokeTokenAsync` with
  `RevocationReasons.UserNotFound` and emits a `LogWarning` on
  `SecurityEventIds.OrphanedTokenRevoked` (4003). Every subsequent hit on this auth service
  is then caught by `RevokedTokenMiddleware`. Logout-all keeps its idempotent 200 (the user
  asked to be logged out, they are); the others return 401. Cross-service revocation is a
  separate known limitation: other consumer services will keep accepting the token until
  natural expiry. Internal Identity
  state (lockout counters, security stamp, password hash) and token claims (`jti`/`sid`/`exp`
  — client already has the JWT) are deliberately omitted. **Note on the wider design:** roles
  are kept in the JWT itself for stateless authorization — every consumer would otherwise
  have to call back on every request to make `[Authorize(Roles=...)]` work, which defeats
  the JWT model. `/me` returning roles is a UI-rendering convenience, not a replacement for
  the token claims.

- [x] ~~**`UserConstants.Admin = "admin"`** is referenced as a username only by the seeder.
  Worth dropping the constant once the seeder is removed (see admin-password TODO above)
  and using `AdminAccountSeedSettings.UserName` instead.~~ Won't fix — the seeder isn't
  going away. Dev still gets a default admin via the seeder for "Just Works" first-run; prod
  uses the same seeder with the password pulled from env var / secret store. The constant
  is still actively consumed, so it's not dead code.

---

## Recommended fix order

1. ~~**Bugs first** — `Logout` HTTP method/auth.~~ All headline bugs in this bucket closed.
   The security-correctness section is now complete bar one feature item (threshold
   escalation on revoked-token replay) and one explicitly-deferred-to-SIEM item
   (behavioural anomaly detection).
2. ~~**Multi-replica blockers**~~ — data-protection key persistence, forwarded-headers,
   migrations-out-of-startup, health checks. All done.
3. **Observability** — structured logging + security events done; OpenTelemetry pending.
4. ~~**Key rotation**~~ — multi-key loader + JWKS + ActiveKeyId + rotation runbook landed.
5. ~~**Recovery redesign** — email-link with single-use stamp-rotating token; rate-limit the
   endpoints.~~ Done — recover endpoint merged into the existing reset-password flow. Rate
   limiting also done as part of the per-endpoint policies sweep.
6. ~~**Refresh-token hashing + rotation-on-use.**~~ Done — full chain landed (hashed
   storage, family-scoped rotation, reuse detection cascade, per-device + everywhere
   logout, cleanup sweep, suspicious-activity email + security event).
7. **Tests + CI** — the next big item. No regression coverage exists for any of the work
   done above.
8. ~~**CORS + standards cleanups**~~ — CORS done; OIDC discovery doc trimmed; RFC 7638
   `kid` thumbprint landed; per-endpoint rate-limit policies in place. **Smaller
   corrections** still open (see section above).

Rough effort estimate to reach "I'd put this in a production gate review with a straight
face": ~2-4 weeks of focused work.
