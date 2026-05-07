# Test projects

Three test projects, one per source project, all using:

- **xUnit** as the runner
- **AwesomeAssertions** for fluent assertions (FluentAssertions fork; no licence concerns)
- **NSubstitute** for mocking (no Moq SponsorLink politics)
- **EF Core SQLite InMemory** for tests that need transactions / `ExecuteUpdateAsync` /
  `ExecuteDeleteAsync` (the EF Core `InMemory` provider rejects all three — SQLite
  InMemory honours them while staying fully self-contained)

All tests follow the **arrange / act / assert** pattern with comments explaining what's
being tested and why. The reasoning matters as much as the assertions — when a test fails
later, a maintainer should be able to read the comments and tell whether the failure
indicates a regression or a deliberate behaviour change.

## Running

```bash
# all three projects
dotnet test Tests/AuthenticationService.Client.Tests/
dotnet test Tests/AuthenticationService.Shared.Tests/
dotnet test Tests/AuthenticationService.Tests/

# or via solution-wide
dotnet test
```

## Coverage

| Project | Tests |
|---|---|
| `AuthenticationService.Client` | 10 |
| `AuthenticationService.Shared` | 78 |
| `AuthenticationService` | 308 |
| **Total** | **396** |

## What's covered

### `AuthenticationService.Client.Tests`
- `AuthenticationServiceOptions` — DataAnnotation Required-field gating, default `RequireHttpsMetadata = true`.
- `ServiceCollectionExtensions.AddAuthenticationServiceJwt` — option binding, JwtBearer registration as default scheme, `TokenValidationParameters` shape (issuer/audience/algorithm/role-claim/MapInboundClaims false), HTTPS override propagation, fluent return.

### `AuthenticationService.Shared.Tests`
- All **DTOs** — DataAnnotation rules pinned (Required, MaxLength, Compare, Phone, EmailAddress) for `RegistrationDto`, `UpdateProfileDto`, `ChangePasswordDto`, `ResetForgottenPasswordDto`, `AuthenticationDto`, `MfaAuthenticationDto`, `ForgotPasswordDto`, `LockAccountDto`, `RefreshTokenDto`, `ResendEmailConfirmationDto`, `EnableMfaRequest`.
- All **Response DTOs** — `ApiResponse` (every mutation method, plus duplicate-key throw and `Successful` round-trip), `AuthenticationResponse` (both factories + every `MfaProviders` value + inherited error pipeline), `EnableMfaResponse` (both constructors), `MeResponse` (shape).
- **Constants** — `ClaimConstants`, `PolicyConstants`, `RolesConstants` (display + normalised), `AuthSchemeConstants` — pinned because each is a wire contract.
- `MfaProviders` enum — declared members + name-string round-trip.
- `Token` model — `required` + `init` immutability contract.

### `AuthenticationService.Tests`

#### Data classes
- All **Settings** — DataAnnotation rules + meaningful defaults for `JWTSettings`, `IdentitySettings` (+ `PasswordSettings`, `UserSettings`, `LockoutSettings`), `AdminAccountSeedSettings`, `HostingSettings`, `ThresholdEscalationSettings`, `DataRetentionSettings`.
- All **Constants** — `SecurityEventIds` (every numeric ID + range bucket pinned via reflection), `RevocationReasons`, `RateLimitPolicies`, `TokenPurposes`, `ApiRoutes`, `WellKnownPaths`, `ResponseConstants`, `EmailSubjects` (uniqueness + non-empty), `ErrorMessages` (each user-facing text pinned), `UriConstants`, `UserConstants`, `PageRouteConstants`.
- **Entities** — `User`, `Role`, `RefreshToken`, `RevokedToken`, `RevokedTokenAccessAttempt` — Required + MaxLength rules, default-value invariants (e.g., `RevokedToken.WarnedAt` defaults null so escalation worker fires fresh).
- **Enums** — `Severity` (numeric ordering), `LoginFailureReason` (member set + names).

#### Logic classes
- **Validators** — every branch of all three:
  - `CustomPasswordValidator<TUser>` — password-matches-username, password-matches-email, case-insensitive matching, happy path.
  - `ReservedUserNameValidator` — reserved name (case-insensitive, with whitespace trim), non-reserved happy, null/empty username, empty deny-list.
  - `AdminAccountSeedSettingsValidator` — named-instance skip, Development bypass, non-Development + dev-default password fail with explicit operator message, custom password success.
- **Helpers**:
  - `AccountHelpers` — both URI builders, including special-character encoding and existing-query-param preservation.
  - `QrCodeHelpers` — PNG magic-byte verification, distinct-input → distinct-output, special-character handling.
- **Middleware**:
  - `RevokedTokenMiddleware` — every of the four paths (no header, empty-token, not-revoked, revoked-with-record-replay), plus null-IP and missing-UA defensive cases.
  - `SecurityHeadersMiddleware` — every header value pinned with rationale; pre-existing-header overwrite case.
- **Extensions**:
  - `HttpRequestExtensions.GetRemoteIpAddress` — both overloads, IPv4 + IPv6, null IP returns empty string.
- **Logging**:
  - `HttpContextLogEnricher` — UA present, UA empty, no `HttpContext`, pre-existing property not overwritten.
- **Services**:
  - `RefreshResult` discriminated union — every case + base-type assignability + record equality.
  - `JwksDocument` / `JwksKey` — JSON wire shape under camelCase policy, empty-keys array, round-trip, structural equality.
  - `EcdsaKeyProvider` — single-key happy, multi-key auto-select, explicit thumbprint select, unknown-thumbprint throws, empty-dir-Dev auto-generates, empty-dir-Prod throws, non-existent dir created, JWKS document cached by reference, doc keys mirror `PublicJsonWebKeys`, repeat dispose safe.
  - `JWTService` — `CreateTokenAsync` (claim shape, FamilyId reuse, refresh-hash-not-raw), `RotateRefreshTokenAsync` (success, garbage-token throw, expired, reuse-cascade, unknown-user), `ValidateExpiredTokenAsync` (valid, foreign-key, garbage), `RevokeTokenAsync` / `GetRevokedTokenAsync` / `RevokeOrphanedTokenAsync`, `RecordRevokedReplayAsync` (Severity.Low for naturally-expired, Medium for still-live, null-UA, oversized-UA truncation, null-ExpiresAt → Medium), `RevokeAllRefreshTokenFamiliesAsync` (only active rows), `RevokeFamilyAsync` (only named family), `GetUserId`, `GetExpiryDateTime`. **29 tests.**
  - `UserService` — `InvalidateUserTokensAsync` (with + without token, empty-string token), plus representative pass-throughs for the renamed Mfa methods (Get/Set/Generate/Verify) and a sample of the rest.
  - `SmsService` — default `IsConfigured = false`, `SendAsync` throws.
  - `QueuedEmailService` (producer side) — sub-millisecond return time pinned; concurrent multi-writer enqueue; queue-full path doesn't throw.
- **Hosted services** (sweep / cleanup methods exposed as `internal` + `InternalsVisibleTo`):
  - `DataRetentionCleanupService.RunCleanupAsync` — old audit rows past TTL deleted, recent kept; expired RevokedTokens / RefreshTokens deleted, live ones kept; empty DB no-op.
  - `RevokedTokenReplayEscalationService.RunSweepAsync` — no replays no-op, warn at threshold (stamps WarnedAt without lock cascade), already-warned doesn't refire, lock at threshold (cascade: lockout-until-MaxValue + revoke-all-families + stamp rotation + email + Critical SIEM), already-locked doesn't refire, missing user logs and skips, email-send-fails doesn't break security action, audit row for unknown jti gracefully skipped.
- **Health checks**:
  - `RedisHealthCheck` — ping succeeds → Healthy, ping throws → Unhealthy with exception, ping hangs past 1s timeout → Unhealthy, outer cancellation already cancelled → Unhealthy.
- **Storage**:
  - `RuntimeDbSeeders` — happy path, admin-already-exists no-op, multi-replica race (Duplicate*Code → benign), real Identity error → ArgumentException, transient DB error (`DbException`) → re-throw for orchestrator reschedule, unexpected error → re-throw, composite `RuntimeDbSeedAsync` entry point.
- **Controllers**:
  - `TestController` — both action methods.
  - `WellKnownController` — JWKS returns cached document by reference, OIDC discovery shape (issuer, jwks_uri, ES256-only).
  - `AccountController.MeAsync` — happy, missing-sub-claim 401, orphan-token (revoke + 401).
  - `AccountController.UpdateProfileAsync` — null body 400, missing-sub-claim 401, orphan-token revoke + 401, no-changes 200 with no DB write, partial update only writes changed fields, phone-change resets confirmation, same-phone doesn't reset.
  - `AccountController.EnableMfaAsync` — orphan, key-already-exists vs needs-reset, invalid-provider, Email path, Phone × (sms-configured, phone-confirmed) matrix with rollback, Authenticator path with QR + key, null-DTO-provider preserves existing user preference.
  - `AccountController.ForgotPasswordAsync` — unknown email 400, unconfirmed email 400, callback URL preserved, default fallback to bundled page.
  - `AccountController.ResetForgottenPasswordAsync` — unknown / unconfirmed 400, identity reset failure surfaces errors, success → invalidate-all-tokens, clear lockout, send notification.
  - `AccountController.ChangePasswordAsync` — missing sub 401, orphan-token revoke + 401, unconfirmed email 400 (no revoke), locked 401, identity error 400 with errors, success → invalidate + clear lockout + reset access-failed + email notification.
  - `AccountController.LockAccountAsync` — unknown email 400, invalid token 401, happy → invalidate + lockout-until-MaxValue + send reset email.
  - `AuthenticationController.AuthenticateAsync` — every branch: unknown email, email-not-confirmed, account locked, wrong password, MFA-required (all three providers), SMS-not-configured, phone-unconfirmed, invalid provider, happy path.
  - `AuthenticationController.MfaAuthenticateAsync` — unknown email, locked, wrong code (failed-attempt + lockout cascade with email), accepted (token + reset).
  - `AuthenticationController.RefreshTokenAsync` — invalid expired-token signature 401, every `RefreshResult` case (Success, NotFound, Expired, Reused with notification email + critical SIEM), Reused-but-no-email gracefully skipped, Reused-but-email-throws still 401.
  - `AuthenticationController.LogoutAsync` — missing sid 401, happy path revokes family + access token.
  - `AuthenticationController.LogoutAllAsync` — missing sub 401, orphan-token idempotent (revoke + Ok), happy path invalidates everything.
  - `RegistrationController.RegisterUserAsync` — null body 400, identity error 400 with errors, happy → role + email + 201, MFA preference applied, no-MFA-preference skips UpdateAsync, exception mid-flow → rollback + 500 with correlation id.
  - `RegistrationController.ConfirmEmailAsync` — unknown email 400, identity rejects token 400, success → security stamp rotated + redirect; allow-listed callback honoured, off-list callback rejected (open-redirect defence) + falls back to default, relative callback honoured as safe.
  - `RegistrationController.ResendConfirmEmailAsync` — unknown 400, already-confirmed 400, fresh send Ok.

## What's deferred (and how to add it)

### Integration tests (Testcontainers)
Unit tests use SQLite InMemory + substituted services. End-to-end auth flow against a real
MySQL container would catch:
- EF query shape divergences between SQLite and MySQL (collation, JSON columns, etc.).
- The full Identity stack against the production-shape schema.
- The `QueuedEmailService` consumer loop end-to-end against a fake SMTP container
  (e.g. MailHog) — currently only the producer side is unit-tested.

These are flagged in the parent `TODO.md` Tier 4.

### `UserService` pass-through methods
A representative sample (`FindByEmailAsync`, `GetMfaEnabledAsync`, `SetMfaEnabledAsync`,
`GenerateMfaTokenAsync`, `VerifyMfaTokenAsync`, `GetValidMfaProvidersAsync`,
`CreateAsync`, `ResetPasswordAsync`, `IsLockedOutAsync`) is covered. The remaining ~15
methods are 1-line `UserManager` delegations — adding 1:1 tests adds little value beyond
compile-time signature checks. A full delegation matrix could be auto-generated via
reflection if exhaustive coverage is later wanted.

### Framework wiring (genuinely tested indirectly via app startup)
The following are pure DI / pipeline registration with no testable behaviour beyond
"app starts" — a separate integration test is the right shape, not unit tests:
- `HostExtensions` (every `Add*` method)
- `WebApplicationExtensions.ConfigureApplicationAsync`
- `DatabaseContext.OnModelCreating` (EF model assertions are typically integration tests)
- `RateLimiterOptionsConfigurator` (testable in principle but requires a real Redis +
  HttpContext fixture; better as integration test).

## How to extend

1. Place tests in the same folder structure as the source class
   (e.g., `AuthenticationService/Services/Foo.cs` → `Tests/AuthenticationService.Tests/Services/FooTests.cs`).
2. Follow the `// arrange` / `// act` / `// assert` pattern with comments explaining
   *why* — not just what — the assertion matters.
3. Use NSubstitute for collaborators; only fall back to a real implementation when
   the collaborator's behaviour is itself part of what's being tested
   (`EcdsaKeyProvider` in `JWTServiceTests` is the canonical example).
4. For DB-backed tests, use SQLite InMemory (see `JWTServiceTests` for the pattern with
   open-connection tracking + `db.ChangeTracker.Clear()` after `ExecuteUpdate*` /
   `ExecuteDelete*` calls to defeat stale-tracker reads).
5. For hosted-service sweep / cleanup logic, drive the `internal` method directly via
   `[InternalsVisibleTo("AuthenticationService.Tests")]` rather than spinning up the
   timer loop (see `DataRetentionCleanupServiceTests` /
   `RevokedTokenReplayEscalationServiceTests` for the pattern).
