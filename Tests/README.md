# Test projects

Three test projects, one per source project, all using:

- **xUnit** as the runner
- **AwesomeAssertions** for fluent assertions (FluentAssertions fork; no licence concerns)
- **NSubstitute** for mocking (no Moq SponsorLink politics)
- **EF Core SQLite InMemory** for tests that need transactions / `ExecuteUpdateAsync`
  (the EF Core `InMemory` provider rejects both — SQLite InMemory honours them while
  staying fully self-contained)

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

## Coverage status

| Project | Public types | Tested types | Tests |
|---|---|---|---|
| `AuthenticationService.Client` | 2 | 2 | 10 |
| `AuthenticationService.Shared` | ~20 (DTOs, models, enums, constants) | all | 78 |
| `AuthenticationService` | ~50 (services, controllers, validators, middleware, etc.) | most | 231 |
| **Total** | | | **319** |

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
- **Storage**:
  - `RuntimeDbSeeders` — happy path, admin-already-exists no-op, multi-replica race (Duplicate*Code → benign), real Identity error → ArgumentException, transient DB error (`DbException`) → re-throw for orchestrator reschedule, unexpected error → re-throw, composite `RuntimeDbSeedAsync` entry point.
- **Controllers**:
  - `TestController` — both action methods.
  - `WellKnownController` — JWKS returns cached document by reference, OIDC discovery shape (issuer, jwks_uri, ES256-only).
  - `AccountController.MeAsync` — happy, missing-sub-claim 401, orphan-token (revoke + 401).
  - `AccountController.UpdateProfileAsync` — null body 400, missing-sub-claim 401, orphan-token revoke + 401, no-changes 200 with no DB write, partial update only writes changed fields, phone-change resets confirmation, same-phone doesn't reset.
  - `AuthenticationController.AuthenticateAsync` — every branch: unknown email, email-not-confirmed, account locked, wrong password, MFA-required (all three providers), SMS-not-configured, phone-unconfirmed, invalid provider, happy path.

## What's deferred (and how to add it)

The task scope was "every public class + every path through every public method." Due
to context budget the items below are **not yet covered**. Each is straightforward to
add following the patterns established in the existing tests; this section exists so a
follow-up developer (or a follow-up AI session) can pick up cleanly.

### Controllers — remaining endpoints
The pattern is established in `AccountControllerMeTests` and
`AuthenticationControllerLoginTests`. Each remaining endpoint mostly needs:
1. happy path, 2. orphan-token-revoke path (where authorised), 3. each documented failure
mode, 4. a SIEM-event-emitted assertion.

Outstanding endpoints:

| Controller | Endpoint | Branches still to cover |
|---|---|---|
| `AccountController` | `EnableMfaAsync` | orphan, key-already-exists vs. needs-reset, invalid-provider, Email path, Phone path × (sms-configured, phone-confirmed) matrix, Authenticator path, MFA-rollback when phone validation fails after `SetMfaEnabledAsync(true)`, happy SIEM event. |
| `AccountController` | `ForgotPasswordAsync` | unknown-email returns 400 (don't leak registration), unconfirmed-email returns 400, default callback URL fallback, callback URL preserved, email sent. |
| `AccountController` | `ResetForgottenPasswordAsync` | unknown email, unconfirmed email, identity reset failure, identity reset success — clears lockout + sends "password changed" notification. |
| `AccountController` | `ChangePasswordAsync` | orphan, wrong old password, identity error, success → invalidate-all-tokens + email notification. |
| `AccountController` | `LockAccountAsync` | unknown email, invalid token, already-locked no-op, happy → invalidate-all-tokens + lockout SIEM event. |
| `AuthenticationController` | `MfaAuthenticateAsync` | unknown user, locked, wrong code → record failed attempt, code accepted → token issued + SIEM event. |
| `AuthenticationController` | `RefreshAsync` | each `RefreshResult` case (Success → 200 + token, NotFound → 401, Expired → 401, Reused → 401 + reuse SIEM event). |
| `AuthenticationController` | `LogoutAsync` / `LogoutAllAsync` | orphan, happy. |
| `RegistrationController` | `RegisterUserAsync` | identity error → BadRequest, transactional commit on success, MFA preference applied, role assigned, confirmation email sent. |
| `RegistrationController` | `ConfirmEmailAsync` (GET) | unknown email, identity error, success → security stamp rotated + redirect to safe callback. |
| `RegistrationController` | `ResendEmailConfirmationAsync` | unknown email returns 200 (don't leak), already-confirmed returns 200, fresh send. |
| `RegistrationController` | `ResolveSafeCallback` (private) — exercised through `ConfirmEmailAsync` | absolute URL on allow-list passes, off-list URL falls back to default + SIEM warn. |

### Hosted services
- `DataRetentionCleanupService` — driven by `PeriodicTimer`. Pure unit tests would need
  a mockable timer abstraction the production code doesn't currently expose. Path forward:
  introduce an `ITimeProvider` / extract the cleanup body into a public method and test
  that directly.
- `RevokedTokenReplayEscalationService` — same shape; same path forward.
- `QueuedEmailService` — `Channel<T>` + persistent SMTP connection. Test by enqueueing
  via `SendEmailAsync` then asserting the dispatcher consumes; SMTP call needs a
  mockable abstraction that doesn't exist yet.

### Health checks
- `RedisHealthCheck` — depends on a real `IConnectionMultiplexer`. Either mock the
  multiplexer to return controlled `IsConnected` values, or run a Redis test container
  via Testcontainers.

### Framework wiring (genuinely tested indirectly via app startup)
The following are pure DI / pipeline registration with no testable behaviour beyond
"app starts" — a separate integration test is the right shape, not unit tests:
- `HostExtensions` (every `Add*` method)
- `WebApplicationExtensions.ConfigureApplicationAsync`
- `DatabaseContext.OnModelCreating` (EF model assertions are typically integration tests)

### Pass-through `UserService` methods
A representative sample is covered. The remaining ~20 are 1-line UserManager
delegations — adding 1:1 tests adds little value beyond compile-time signature checks.
A full delegation matrix could be auto-generated via reflection if exhaustive coverage
is later wanted.

## How to extend

1. Place tests in the same folder structure as the source class
   (e.g., `AuthenticationService/Services/Foo.cs` → `Tests/AuthenticationService.Tests/Services/FooTests.cs`).
2. Follow the `// arrange` / `// act` / `// assert` pattern with comments explaining
   *why* — not just what — the assertion matters.
3. Use NSubstitute for collaborators; only fall back to a real implementation when
   the collaborator's behaviour is itself part of what's being tested
   (`EcdsaKeyProvider` in `JWTServiceTests` is the canonical example).
4. For DB-backed tests, use SQLite InMemory (see `JWTServiceTests` for the pattern with
   open-connection tracking + `db.ChangeTracker.Clear()` after `ExecuteUpdate*` calls
   to defeat stale-tracker reads).
