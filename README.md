# AuthenticationService

[![CI](https://github.com/Skuzzle-UK/AuthenticationService/actions/workflows/ci.yml/badge.svg)](https://github.com/Skuzzle-UK/AuthenticationService/actions/workflows/ci.yml)

Centralised identity & access service for the platform. Issues short-lived ES256-signed
JWTs and exposes a JWKS endpoint so consuming microservices can validate them without
sharing secrets.

---

## Solution layout

### Production projects

| Project | Purpose |
|---|---|
| `AuthenticationService` | The HTTP API: registration, login, MFA, refresh (with rotation + reuse detection), per-device & all-device logout, password reset (which is also the account-unlock path), JWKS/OIDC discovery. |
| `AuthenticationService.Shared` | DTOs, view models, and wire-contract constants (claim names, role values, policy names, auth scheme). Shared between the API, the client library, and any non-.NET clients (mobile, frontend, etc). |
| `AuthenticationService.Client` | The drop-in NuGet/project reference for **other microservices** that need to validate tokens. Provides `AddAuthenticationServiceJwt(...)` and brings `AuthenticationService.Shared` in transitively so consumers get the constants without an extra reference. |
| `AuthenticationService.ServiceDefaults` | Shared library that wires OpenTelemetry / health-checks / service-discovery defaults into any .NET project that joins the Aspire AppHost graph. Currently only the auth service itself; future microservices reference this for free. Production deploys do **not** ship Aspire — ServiceDefaults still adds OTel without it. |
| `ExampleConsumer` | A small minimal-API microservice that demonstrates the client library end-to-end. Useful as a smoke test and as a copy-paste starting point for new services. See [Try it end-to-end](#try-it-end-to-end). |

### Dev / test orchestration (not deployed)

| Project | Purpose |
|---|---|
| `AuthenticationService.AppHost` | .NET Aspire orchestrator. Hitting F5 here launches the auth service as a normal .NET process and spins up MySQL / Redis / smtp4dev as containers with connection strings auto-injected. Aspire dashboard at `https://localhost:17282` shows live traces, logs, and metrics from every resource in the graph. **Dev/test only — never deployed.** |
| `Tests/AuthenticationService.Client.Tests` | Unit tests for the client library (10 tests). |
| `Tests/AuthenticationService.Shared.Tests` | Unit tests for the shared DTOs / constants (78 tests). |
| `Tests/AuthenticationService.Tests` | Unit tests for the auth service — every controller endpoint, validator, middleware, helper, hosted-service sweep, etc. (308 tests). |
| `AuthenticationService.IntegrationTests` | End-to-end scenario tests using `Aspire.Hosting.Testing` to boot the whole AppHost graph in-process. Real MySQL, Redis, smtp4dev. (8 scenarios, see [Testing](#testing) below.) |

---

## User flow (end-user perspective)

1. **Register** with email + password. Username is a separate display field; a deny-list (`IdentitySettings.User.ReservedUserNames` in config) blocks claims on names that should remain reserved for system / platform identities (`administrator`, `root`, `noreply`, `support`, etc.).
2. **Confirm email** via the link sent to the inbox.
3. **Authenticate** with email/username + password — receive a JWT (5 min) + refresh token (5 days). The pair belongs to a "session family" identified by the `sid` claim — a single login is one family; multiple devices each get their own.
4. (Optional) **Enable MFA** — server returns a QR code.
5. With MFA enabled: authenticate with credentials → server returns "MFA required" → submit MFA code → receive token.
6. **Refresh** before expiry. Each refresh issues a new pair and *immediately consumes* the presented refresh token. Presenting an already-consumed token (e.g., a stolen one being replayed) is treated as theft: every refresh-token family for the user is revoked, the security stamp is rotated, and a "suspicious activity" email is sent.
7. **Logout (per device)** revokes the caller's session family and adds the current access token to the deny-list. Other devices the user is signed in on are unaffected.
8. **Logout-all** revokes every session family for the user and rotates the security stamp — all outstanding access tokens die immediately.
9. **Account locked or password forgotten?** The `forgotpassword` flow is the unlock path too — a successful reset clears any active lockout.

---

## Prerequisites

- **.NET 10 SDK**
- **MySQL 8** (any reachable instance — local, container, or managed)
- **Redis** for data-protection key persistence (any reachable instance — local, container, or managed). For local dev: `docker run -d -p 6379:6379 redis:alpine` or a native install. Defaults to `localhost:6379` in `appsettings.json`.
- An **SMTP relay** for outbound email (registration confirmation, MFA codes, account recovery). For local dev, [Papercut SMTP](https://github.com/ChangemakerStudios/Papercut-SMTP) or MailHog work fine.

---

## Development setup

### 1. Clone and restore

```bash
git clone <repo-url>
cd AuthenticationService
dotnet restore
```

### 2. Configure local secrets

The default `appsettings.json` ships with placeholder values that are **safe enough for first-run** but should be overridden via [User Secrets](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets) for anything sensitive:

```bash
cd AuthenticationService
dotnet user-secrets set "ConnectionStrings:MySQL" "server=localhost;port=3306;database=AuthenticationService;user=root;password=<your-password>;"
dotnet user-secrets set "AdminAccountSeedSettings:Password" "<your-strong-password>"
dotnet user-secrets set "EmailServerSettings:Password" "<smtp-password>"
```

Anything you don't override falls back to the values in `appsettings.json` / `appsettings.Development.json`.

### 3. Run

Two options.

**Option A — directly (you supply MySQL / Redis / SMTP yourself):**

```bash
dotnet run --project AuthenticationService
```

**Option B — via .NET Aspire (recommended; auto-spins MySQL / Redis / smtp4dev as
containers):**

```bash
dotnet run --project AuthenticationService.AppHost
```

In Visual Studio: set `AuthenticationService.AppHost` as the startup project and F5.
Aspire pulls / starts the container dependencies, injects connection strings, then
launches the auth service as a normal .NET process (debugger attaches normally; no
container indirection). The Aspire dashboard opens in a browser showing live logs,
traces, metrics, and clickable links into each container's web UI (e.g., smtp4dev's
inbox at the http endpoint shown on the dashboard's `smtp4dev` resource).

Aspire needs Docker (or any Docker-compatible runtime — Rancher Desktop, Podman
Desktop). Production deploys do NOT use Aspire — the auth service ships on its own
with operator-supplied infrastructure connection strings.

On the first run you should see:

```
warn: AuthenticationService.Services.EcdsaKeyProvider[0]
      No signing keys found in 'keys'. Generating a new ES256 key for Development.
      DO NOT use this key in production.
info: ...
      Application started. Listening on: https://localhost:53217
```

A new `keys/jwt-signing.pem` is created next to the project. **The whole `keys/` directory is gitignored**; do not commit it. Each developer gets their own local key — tokens you issue locally only validate against your own auth service.

If you ever want to invalidate every dev token, delete the directory contents and restart. Tokens expire in 5 minutes anyway.

Database migrations run automatically on startup (`app.RunMigrations()`).

### 4. Seeded admin account

A default admin is seeded on first run. Most fields come from `appsettings.json`:

| Field | Default | Source |
|---|---|---|
| Email | `email@email.com` | `appsettings.json` |
| First name | `Administrator` | `appsettings.json` |
| Country | `United Kingdom` | `appsettings.json` |
| **Password** | `Pa5$word123` | **`appsettings.Development.json` (dev only)** |

The password lives in `appsettings.Development.json` deliberately so `dotnet run` works first time without anyone having to think about credentials. **Outside Development the service refuses to start unless `AdminAccountSeedSettings:Password` is supplied via env var, user-secrets, or a secret store** — and it rejects the dev default verbatim, so a copy-pasted dev config can't accidentally reach prod. See the production-deployment section for the override mechanism.

If you'd rather not use the dev default even locally, override it via user-secrets:

```bash
dotnet user-secrets set "AdminAccountSeedSettings:Password" "<your-strong-password>"
```

### 5. Try it out via Swagger

Hit `https://localhost:<port>/swagger`.

1. Call `POST /api/Authentication/authenticate` with the seeded admin credentials.
2. Copy the `token.value` field from the response.
3. Click the **Authorize** button (top right), paste the token (no `Bearer ` prefix), Authorize, Close.
4. Call `GET /api/Test` — should return 200 with `"Test succeeded"`.

---

## Try it end-to-end

The `ExampleConsumer` project simulates a separate microservice that trusts tokens issued by `AuthenticationService`. It validates them by fetching the JWKS — no shared secrets, no extra config.

### Run both services

In two terminals (or via VS multi-startup):

```bash
# Terminal 1
dotnet run --project AuthenticationService    # https://localhost:53217

# Terminal 2
dotnet run --project ExampleConsumer          # https://localhost:50500
```

The example consumer's Swagger lives at `https://localhost:50500/swagger`. It exposes three endpoints:

| Endpoint | Auth | Behaviour |
|---|---|---|
| `GET /` | Anonymous | Returns a hello message. |
| `GET /me` | Authenticated | Returns the caller's identity (name, roles, jti, sub) from the validated token. |
| `GET /admin` | Admin role | Restricted to tokens whose `role` claim contains `Admin`. |

### Walk-through

1. Open `https://localhost:53217/swagger` (the **auth service**) and call `POST /api/Authentication/authenticate` with the seeded admin creds. Copy `token.value` from the response.
2. Open `https://localhost:50500/swagger` (the **example consumer**).
3. Click **Authorize**, paste the token, Authorize, Close.
4. Call `GET /me` → 200 with your username, roles `["DefaultUser","Admin"]`, the `jti` (per-token ID), and the `sub` (stable user ID — the value to use as a foreign key in any consumer DB).
5. Call `GET /admin` → 200 (because your token carries the `Admin` role).
6. Call `GET /` → 200 anonymously, no token needed.

### Negative tests worth running

- **Tamper with the token.** Change one character in the middle of the JWT and retry — `/me` returns 401 because the signature no longer verifies.
- **Wait > 5 minutes**, then retry — 401, expired (`exp` claim).
- **Stop the auth service before the consumer starts** — the consumer fails fast at startup (can't reach the discovery endpoint).
- **Restart the auth service so a new dev key is generated** — old tokens stop validating; the consumer auto-picks up the new JWKS at next refresh.
- **Replay a consumed refresh token.** Authenticate, hit `/refresh` once successfully, then hit `/refresh` again with the *original* (now-consumed) refresh token. Expect 401, plus a `RevocationReason = "reuse_detected"` row in `RefreshTokens` for every active family for the user, plus a `LogWarning` event in the auth service logs. (Email send may also fire if SMTP is reachable.)
- **Per-device logout isolation.** Log in twice with the same admin account (two browser sessions). Hit `/logout` from one — the other should keep working until you also `/logout` it (or `/logoutall` from either). Inspect the `RefreshTokens` table to see the per-family revocation.
- **Restart the auth service WITHOUT restarting Redis.** Outstanding email-link tokens (request a password reset, don't click the link, restart the service, click the link) should still work — proof that the data-protection key ring survived restart via Redis persistence. Restart Redis without persistence configured and the link will be broken — proof that AOF/RDB matters.
- **Try registering with a reserved username.** `POST /api/Registration/register` with `{ "UserName": "Administrator", ... }` should return 400 with an `errors.ReservedUserName` entry. Same for any of the names in `IdentitySettings.User.ReservedUserNames` (case-insensitive). Try `"alice"` and you should get past the username validator (succeeds, or fails on a different rule).
- **Replay a consumed email-confirmation link.** Click the confirmation link in the registration email — the email is now confirmed. Click the same link again — should fail because the security stamp rotated on the first successful confirm, invalidating the token.

### What's actually happening

When you start the consumer:

1. JwtBearer hits `https://localhost:53217/.well-known/openid-configuration`.
2. The discovery doc points at `https://localhost:53217/.well-known/jwks.json` and declares `issuer = https://auth.example.com`.
3. JwtBearer fetches the JWK, caches it, and uses it to validate every incoming token's signature against the `kid` in the token header.
4. It also checks `iss == https://auth.example.com`, `aud == platform-api`, and `exp > now`.

> **Common gotcha:** if the consumer's `Authority` setting points at the wrong port, OIDC discovery silently fails — JwtBearer catches the connection error and carries on with no signing keys. The result is a `401` with `"The signature key was not found"` on every request, even with a perfectly valid token. Always verify that `Authority` in `ExampleConsumer/appsettings.json` (and in any new consumer service) matches the port reported by the auth service's `launchSettings.json` (`AuthenticationService/Properties/launchSettings.json`). The `Issuer` value must also match `JWTSettings.ValidIssuer` in the auth service's `appsettings.json`.

There is **no shared secret** between the two services. The consumer never sees the signing key.

---

## Testing

Four test projects, ~404 tests total. Two layers — fast unit tests for everyday feedback,
slower integration tests for the cross-cutting / DB-shape stuff.

### Layout

| Project | Type | Tests | Duration | When |
|---|---|---|---|---|
| `Tests/AuthenticationService.Client.Tests` | Unit | 10 | ~0.2s | Every commit |
| `Tests/AuthenticationService.Shared.Tests` | Unit | 78 | ~0.1s | Every commit |
| `Tests/AuthenticationService.Tests` | Unit | 308 | ~3s | Every commit |
| `AuthenticationService.IntegrationTests` | Integration | 8 | ~60s | Every PR |

Stack: **xUnit** runner, **AwesomeAssertions** for fluent assertions, **NSubstitute**
for mocking, **EF Core SQLite InMemory** for unit tests that need EF, **.NET Aspire**
for integration tests.

### Running

```bash
# Fast feedback — unit tests across all projects (~3s)
dotnet test Tests/

# Integration tests (~60s — boots real MySQL + Redis + smtp4dev containers)
dotnet test AuthenticationService.IntegrationTests/

# Everything
dotnet test
```

Integration tests need Docker (or a Docker-compatible runtime — Rancher Desktop, Podman
Desktop). The first run pulls the MySQL / Redis / smtp4dev images (~30s); subsequent
runs reuse them and finish in under a minute.

### What's covered

- **Unit tests** cover every public method on every public class — controllers, services,
  validators, middleware, helpers, hosted services. Coverage map at
  [`Tests/README.md`](Tests/README.md).

- **Integration tests** cover seven end-to-end scenarios that exercise real
  infrastructure (real MySQL, real Redis, real SMTP via smtp4dev):

  | # | Scenario | Asserts |
  |---|---|---|
  | 1 | Register → confirm email → login | Full onboarding pipeline; QueuedEmailService delivery; data-protection-protected confirmation token |
  | 2 | Refresh token rotation | Old refresh row consumed in MySQL, new row in same family |
  | 3 | Refresh token reuse cascade | Reuse triggers full nuke: all families revoked, security stamp rotated, suspicious-activity email sent |
  | 4 | Password change → "wasn't me" lock | Lock token round-trips through email; account locked indefinitely |
  | 5 | Rate limiter integration | Burst against `/authenticate` trips the global 4/10s cap (real Redis Lua scripts) |
  | 6 | Threshold escalation worker | `RunSweepAsync` against real MySQL stamps `LockedAt` + fires lock cascade |
  | 7 | JWKS / OIDC discovery | A consumer using only the published JWKS can validate a JWT issued by the auth service — the actual production contract |

### About `.NET Aspire`

Hitting F5 on `AuthenticationService.AppHost` is the cleanest dev workflow:

1. Aspire boots MySQL, Redis, and smtp4dev as containers.
2. Connection strings flow into the auth project as env-var overrides — no manual config.
3. The auth service runs as a normal `dotnet run` process so debugger / edit-and-continue work.
4. Aspire dashboard opens in a browser showing live logs, traces, metrics, and clickable
   endpoints to each container's UI (e.g., the smtp4dev inbox).

Plain `dotnet run --project AuthenticationService` still works against any MySQL / Redis
/ SMTP you've configured in `appsettings.json` — Aspire is just an alternative dev
front-end. **Production deploys do not include the AppHost** — the auth service ships
on its own.

### Bugs the integration tests caught

Three production-affecting bugs the unit tests couldn't have caught (different SQL
semantics between SQLite-InMemory and Oracle's `MySql.EntityFrameworkCore`):

1. **`DateOnly` round-trip** — Oracle's MySQL provider can't deserialise DATE columns
   back into `DateOnly`. Fixed via `ValueConverter` in `DatabaseContext.OnModelCreating`.
2. **`DateTimeOffset.MaxValue` overflow** — Oracle's provider tries to write the
   fractional-second precision past MySQL's DATETIME max. Fixed via
   `LockoutDurations.Indefinite` (`9999-12-31T00:00:00Z`).
3. **`Contains-on-collection` SQL translation** — `Where(t => list.Contains(...))` errors
   out on Oracle's provider. Fixed via per-jti loop in
   `RevokedTokenReplayEscalationService`.

All three would be obviated by migrating to `Pomelo.EntityFrameworkCore.MySql` — see
[`TODO.md`](TODO.md) Tier 4.

---

## Configuration reference

All settings are bound from `appsettings.json` and validated at startup.

### `JWTSettings`

| Key | Description |
|---|---|
| `PrivateKeyDirectory` | Directory containing one or more ECDSA private keys in PEM format (`*.pem`). Relative paths resolve against the content root. Every key in the directory is loaded; all are published in the JWKS so consumers can validate tokens signed by any of them. **Must contain at least one key in non-Development environments** (no auto-generation). In Development, an empty directory triggers a one-time auto-generated key so `dotnet run` works first time. |
| `ActiveKeyId` | The `kid` (JWK thumbprint) of the key used to sign newly-issued tokens. `"auto"` (default) picks the first key found — fine for single-key operation; set explicitly during a rotation cutover so the active signer is unambiguous. |
| `ValidIssuer` | Stamped into the `iss` claim. Consumers validate against this. |
| `ValidAudience` | Stamped into the `aud` claim. Currently `"platform-api"` — every consuming microservice must use the same value. |
| `ExpiryInMinutes` | Access token TTL. Short by design. |
| `RefreshTokenExpiryInDays` | Refresh token TTL. |

### `AdminAccountSeedSettings`

Seeds a single admin user on first startup. All fields except `LastName`/`PhoneNumber`/`PhoneNumberConfirmed` are required.

### `EmailServerSettings`

SMTP credentials for outbound email (registration confirmation, MFA, recovery, lockout notices). Email send happens off the request thread via an in-memory queue + background dispatcher — see [§12 — Email dispatch](#12-email-dispatch).

### `DataRetentionSettings`

Controls the `DataRetentionService` background sweep that prunes expired audit + token rows.

| Key | Description |
|---|---|
| `CleanupIntervalInHours` | How often the sweep runs. Default 12. |
| `RevokedReplayTTLInDays` | How long `RevokedTokenAccessAttempt` audit rows are retained after creation. Default 90. `RevokedTokens` and `RefreshTokens` are pruned by their own natural `ExpiresAt`, no separate TTL. |

### `PublicUrlSettings`

Where this service is publicly reachable. Used by background workers (e.g. the threshold-escalation lock email) to build links — they have no `HttpContext` to derive the URL from.

| Key | Description |
|---|---|
| `BaseUrl` | Scheme + host (+ optional port) of the auth service from a user's browser. No trailing slash. Required outside Development; the dev-only default in `appsettings.Development.json` is `https://localhost:53217`. |

### `HostingSettings`

Per-deployment flags that let the same Docker image run as either an API replica or a worker replica. See [§7a — Split API + worker deployments](#7a-split-api--worker-deployments-multi-replica) for the multi-replica K8s pattern.

| Key | Description |
|---|---|
| `BackgroundWorkersEnabled` | Default `true`. Set to `false` on API replicas of a split deployment so only the dedicated worker pod runs the cleanup sweep + threshold-escalation worker. |
| `MaxRequestBodySizeInKilobytes` | Default `1024` (1 MB). Cap on inbound request body size, in KB — Kestrel's own default of 30 MB is far larger than any auth endpoint legitimately needs, so we cap tight to shrink the DoS surface. Range: `1` to `30720` (30 MB — past that the config cap stops helping since Kestrel's own default kicks in). Raise if a future endpoint accepts larger payloads (e.g. avatar upload). |

### `IdentitySettings`

ASP.NET Core Identity tuning — password rules, user-creation rules, lockout policy. Defaults match NIST 800-63B / OWASP guidance and reasonable lockout protection. Most deployments shouldn't need to change these; the block in `appsettings.json` is a reference for what's tunable.

| Key | Default | Notes |
|---|---|---|
| `Password.RequiredLength` | `12` | NIST 800-63B / OWASP. Bump to 14 or 16 for higher-assurance environments. |
| `Password.RequireDigit` | `true` | |
| `Password.RequireLowercase` | `true` | |
| `Password.RequireUppercase` | `true` | |
| `Password.RequireNonAlphanumeric` | `true` | |
| `Password.RequiredUniqueChars` | `1` | Effectively no restriction. NIST recommends *not* enforcing — uniqueness rules push users toward predictable patterns. Exposed for compliance frameworks that require it. |
| `User.RequireUniqueEmail` | `true` | Don't disable — the password-reset flow looks users up by email. |
| `User.AllowedUserNameCharacters` | (Identity's default — letters, digits, `-._@+`) | Tighten by removing characters. E.g. drop `+` if usernames are emails and you want to block gmail-alias style. Affects new registrations only. |
| `User.ReservedUserNames` | (platform defaults — see `IdentitySettings.cs`) | Usernames blocked at registration. Setting this in config **replaces** the default list — copy the defaults out and extend rather than start from scratch. Useful for adding org-specific reserved names (`finance`, `infosec`, `payroll`, etc.). |
| `Lockout.AllowedForNewUsers` | `true` | Don't disable — brand-new accounts need the same brute-force protection as existing ones. |
| `Lockout.DefaultLockoutDurationInMinutes` | `2` | Auto-clears at this duration. Short by design — legitimate user typos shouldn't pay a long penalty. |
| `Lockout.MaxFailedAccessAttempts` | `3` | Tight enough to deter credential stuffing, generous enough for typos. |

### `ThresholdEscalationSettings`

Tuning knobs for the `RevokedTokenReplayEscalationService` background worker. See [§9a — Threshold escalation on revoked-token replay](#9a-threshold-escalation-on-revoked-token-replay) for the full picture.

| Key | Description |
|---|---|
| `Enabled` | Master kill switch. Default `true`. |
| `SweepIntervalInMinutes` | How often the worker scans for replays. Default 1. |
| `WindowInMinutes` | Sliding-window size for both thresholds. Default 5. |
| `WarnThreshold` | Replay count that emits a Warning-level SIEM event. Default 2. |
| `LockThreshold` | Replay count that locks the account + emails the user. Default 5. |

### `DataProtectionSettings`

ASP.NET Core's data-protection key ring is persisted to Redis (required) and optionally protected by a certificate. Identity tokens (password reset, email confirmation, MFA, lockout) are signed with this ring — without persistence, every replica restart invalidates outstanding email-link tokens.

| Key | Description |
|---|---|
| `RedisKey` | Hash key under which the data-protection keys are stored. Default `"AuthService:DataProtectionKeys"`. Must be unique per app sharing a Redis instance. |
| `ApplicationName` | Data-protection isolation name. Replicas of this service must share it; different apps must not. **Do not change once deployed** — invalidates all outstanding Identity tokens. |
| `Certificate.PfxPath` | (Optional) Path to a PFX file containing the cert + private key used to encrypt the key ring at rest. When absent, keys sit in Redis as readable XML — acceptable on a controlled network during initial rollout, but should be populated before the service is exposed broadly. |
| `Certificate.PfxPassword` | (Optional) Password for the PFX. |

### `CorsSettings`

Browser-based clients running on a different origin from the auth service need explicit allow-listing.

| Key | Description |
|---|---|
| `AllowedOrigins` | List of origins (scheme + host + port, no trailing slash) permitted to call the API. Empty list blocks all cross-origin traffic. Wildcards are not supported — explicit allow-list only. |

The default policy pins HTTP methods to `GET / POST / OPTIONS` and headers to `Authorization / Content-Type / Accept`. `AllowCredentials` is intentionally off because JWT bearer tokens travel in the `Authorization` header, not in cookies — flipping it on would forbid wildcards we already don't allow and add a security trap.

`appsettings.Development.json` ships with permissive defaults for common local-dev frontend ports (`http(s)://localhost:3000`, `:4200`, `:5173`) covering React, Angular, and Vite. Production `appsettings.json` ships empty — operators must explicitly override `CorsSettings:AllowedOrigins` for the platform's front-end origins.

### `ForwardedHeadersSettings`

Trust list for the `UseForwardedHeaders` middleware. Behind a load balancer / reverse proxy these MUST be populated, otherwise audit IPs and the rate-limiter's IP partition will all be the proxy's IP rather than the real client. Local-dev with no proxy can leave both empty.

| Key | Description |
|---|---|
| `KnownNetworks` | List of CIDR blocks for trusted upstream proxies (e.g. `["10.0.0.0/8"]`). Most production setups want this. |
| `KnownProxies` | List of specific proxy IPs (e.g. `["203.0.113.10"]`). Use when the LB IPs are stable and explicitly known. |

Only `X-Forwarded-For` and `X-Forwarded-Proto` are honoured. `X-Forwarded-Host` is intentionally not honoured (host-header attack surface).

### `ConnectionStrings`

| Key | Description |
|---|---|
| `MySQL` | EF Core connection string for the auth database. |
| `Redis` | StackExchange.Redis connection string for the data-protection key ring. Required in every environment — startup throws on empty. Defaults to `localhost:6379` for local dev. |

---

## Production deployment

### 1. Generate the signing key

Auto-generation only happens in Development. Generate the key once and inject it via your secret store. From any machine with .NET / OpenSSL:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out jwt-signing.pem
```

(Or use the dev-generated key from a `dotnet run`.)

The file looks like:

```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBl...
-----END EC PRIVATE KEY-----
```

**Treat this file like a database password.** Anyone holding it can mint valid tokens.

### 2. Inject the key

The app reads every `*.pem` file in the configured `PrivateKeyDirectory`. Pick whichever delivery mechanism your platform offers — the directory mount + file naming is the only contract:

- **Docker:** `-v /host/secrets/auth-keys:/app/keys:ro`
- **Docker Compose secrets:** mount each PEM under `/run/secrets/` and project them into `/app/keys/` via a tmpfs.
- **Kubernetes:** create a `Secret` containing one or more PEM keys, mount it as a directory via `volumes` + `volumeMounts.mountPath`.
- **Azure / AWS:** Key Vault / Secrets Manager → init-container writes each PEM into a shared `tmpfs` volume the app reads.

If the directory is empty in non-Development environments the service refuses to start with a clear error. The filename itself is irrelevant — the `kid` is computed from the public-key thumbprint, not the filename.

### 3. Provision Redis

The data-protection key ring is persisted to Redis. **Without it, the service will refuse to start.** Two things matter for the deploy:

- **Reachability.** Set `ConnectionStrings__Redis` to whatever the platform's Redis endpoint is (host:port, or full StackExchange.Redis connection string for clustered/auth'd setups).
- **Persistence.** Confirm with the platform team that the Redis instance has AOF or RDB persistence enabled. If it's a pure-cache Redis that gets wiped on restart, every outstanding email-link token (password reset, email confirmation, MFA codes, lockout links) breaks whenever Redis restarts. Most production Redis has persistence on, but explicitly confirm.

If the Redis is shared with other apps, the `DataProtectionSettings:RedisKey` and `ApplicationName` together provide isolation — keep them unique per app.

### 4. Configure data-protection at-rest encryption (recommended)

Without a protection certificate, the data-protection keys sit in Redis as readable XML. Anyone with read access to the Redis DB can extract them and forge anti-forgery tokens / decrypt protected payloads offline.

To wrap the keys with an X.509 cert at rest:

1. Provision a cert (PFX file with private key) via your platform's certificate-management story.
2. Mount it into the container — same delivery mechanisms as the JWT signing key (Docker volume, K8s Secret, Vault sidecar, etc).
3. Set:

   ```bash
   DataProtectionSettings__Certificate__PfxPath=/run/secrets/data-protection.pfx
   DataProtectionSettings__Certificate__PfxPassword=<from-secret-store>
   ```

The cert and the JWT signing key are independent and rotate on different schedules. Both should live in your secret store.

### 5. Configure forwarded headers (if behind a proxy)

If the service is deployed behind a load balancer / reverse proxy / ingress (which it almost certainly is in any corporate setup), populate `ForwardedHeadersSettings` with the proxy's network range. Without this, every audit IP recorded will be the LB's address rather than the real client.

```bash
ForwardedHeadersSettings__KnownNetworks__0=10.0.0.0/8
ForwardedHeadersSettings__KnownProxies__0=203.0.113.10
```

(Either of `KnownNetworks` or `KnownProxies` is fine; usually you'd populate `KnownNetworks` with the LB subnet.)

The middleware also uses `X-Forwarded-Proto` to detect TLS-terminated-at-the-LB deployments. Without it, `app.UseHttpsRedirection()` would loop because the app sees an HTTP connection from the LB and tries to redirect to HTTPS, which the LB receives back and forwards as HTTP again.

### 6. Override config via environment variables

ASP.NET Core's standard double-underscore mapping applies:

```bash
JWTSettings__PrivateKeyDirectory=/run/secrets/auth-keys
JWTSettings__ValidIssuer=https://auth.example.com
JWTSettings__ValidAudience=platform-api
ConnectionStrings__MySQL=server=...
ConnectionStrings__Redis=redis.internal:6379
AdminAccountSeedSettings__Password=<one-time-bootstrap-password>   # REQUIRED outside Development; service refuses to start if missing or set to the dev default
EmailServerSettings__Password=<smtp-secret>
DataProtectionSettings__Certificate__PfxPath=/run/secrets/data-protection.pfx
DataProtectionSettings__Certificate__PfxPassword=<from-secret-store>
ForwardedHeadersSettings__KnownNetworks__0=10.0.0.0/8
CorsSettings__AllowedOrigins__0=https://app.example.com
RunMigrationsAtStartup=false
```

### 7. Database migrations

Migrations are applied at startup in Development (so a fresh `dotnet run` Just Works) but should be applied **out-of-band** in production by the deploy pipeline. Set:

```bash
RunMigrationsAtStartup=false
```

…in the production environment. With this flag off, the application **does not** run `Database.Migrate()` on startup — it just logs a message and continues. The deploy pipeline (init container / K8s Job / Helm hook / CI step) is expected to run:

```bash
cd AuthenticationService
dotnet ef database update
```

…against the production DB before the new replicas roll out.

**Why opt out in production:**

- **Avoids multi-replica startup races.** N replicas all calling `Database.Migrate()` simultaneously serialize at the DB lock level, but produce deadlock noise in startup logs and occasional retry-storms.
- **Failed migrations stay visible.** A pipeline-level migration failure stops the rollout cleanly. A startup-level migration failure looks like a generic pod crash that the orchestrator restarts in a loop.
- **Lets you preview the SQL.** `dotnet ef migrations script` can be run in CI before the actual deploy, code-reviewed, and tested against a staging DB.
- **Lets you roll back.** With out-of-band migrations the deploy pipeline can stop at the migration step if anything looks wrong, before the new app version actually goes live.

In Development the default (`RunMigrationsAtStartup=true`) is preserved so devs don't have to remember a separate step.

### 7a. Split API + worker deployments (multi-replica)

For a multi-replica K8s deployment, run the same Docker image as **two separate Deployments**:

- **API Deployment** (`replicas: 3+`). Handles HTTP traffic. Background workers disabled.
- **Worker Deployment** (`replicas: 1`). Runs the cleanup sweep + threshold-escalation worker. Not in the API's K8s Service so no traffic is routed to it.

Why split: the workers (`DataRetentionCleanupService`, `RevokedTokenReplayEscalationService`) shouldn't run on every API replica. With N replicas all running the threshold-escalation worker, two replicas can simultaneously cross a threshold for the same token and both fire the warn/lock event — duplicate SIEM events, duplicate notification emails to the user. Splitting the workers onto a single dedicated replica eliminates the race.

Gated by one config flag, default `true` (so existing single-deployment setups don't change behaviour):

```bash
# API Deployment
HostingSettings__BackgroundWorkersEnabled=false

# Worker Deployment (default; can also be omitted)
HostingSettings__BackgroundWorkersEnabled=true
```

Example K8s manifest sketch:

```yaml
# API Deployment — handles traffic, no workers
apiVersion: apps/v1
kind: Deployment
metadata: { name: auth-api }
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: auth
          image: auth-service:v1
          env:
            - name: HostingSettings__BackgroundWorkersEnabled
              value: "false"
            # ... other env vars (DB, Redis, JWT settings, etc.)
---
# Worker Deployment — runs the workers, no traffic
apiVersion: apps/v1
kind: Deployment
metadata: { name: auth-worker }
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: auth
          image: auth-service:v1
          # No HostingSettings__BackgroundWorkersEnabled override needed — defaults to true
          env:
            # ... same env as API for DB / Redis / etc.
---
# Service routes only to the API deployment (selector matches API's labels, not worker's)
apiVersion: v1
kind: Service
metadata: { name: auth-api }
spec:
  selector:
    app: auth-api
  ports: [...]
```

The worker pod still binds web ports and exposes `/livez` / `/readyz` (plus `/healthz` for ops debugging) so K8s can probe it normally — there's no special "worker mode" startup, just a config flag. If the worker pod dies, K8s restarts it; until then the workers aren't running. That's acceptable: the cleanup sweep runs every 12h and the threshold-escalation sweep every minute, so a few-minute worker outage causes at most some delayed audit cleanup and a delayed lock-event for an actively-attacked account. Nothing data-corrupting.

If you want auto-failover (worker pod dies → another picks up immediately) the right tool is leader election via a Redis-backed distributed lock. Worth the complexity if your platform's SLA demands it; otherwise the single-replica worker pattern is simpler and sufficient for an auth service's background-task volume.

### 8. HTTPS / hostname

Production must be HTTPS. Consumers configured with `RequireHttpsMetadata = true` (the default) will refuse to fetch JWKS over HTTP.

The **public hostname of the auth service is the contract** — this is the `Authority` URL every consuming microservice points at. Pick it deliberately and avoid changing it (e.g. `https://auth.example.com`, not the load-balancer's hostname).

#### `Authority` and `Issuer` — make them match in production

The auth service has two distinct settings that *look* similar:

- **`JWTSettings.ValidIssuer`** — a *logical name* stamped into every token's `iss` claim. Consumers validate `iss` against this string. It's an identity, not an address.
- **`Authority`** (consumer-side) — the *network URL* where consumers fetch the JWKS / OIDC discovery doc. It's a routing target.

In dev these diverge: `ValidIssuer` is `https://auth.example.com` (a stable logical name), but consumers point `Authority` at `https://localhost:53217` (where the auth service actually runs). The `ExampleConsumer` config explicitly sets *both* `Authority` and `Issuer` so the divergence works — JwtBearer fetches keys from one URL and validates `iss` against the other.

**In production, terminate TLS at a reverse proxy / load balancer with the canonical hostname that matches `JWTSettings.ValidIssuer`.** Once the network URL and the logical issuer are the same string (e.g. both `https://auth.example.com`), JwtBearer's defaults Just Work and consumers no longer need to override `ValidIssuer` separately — they can just set `Authority` and let the issuer be inferred from the discovery doc.

If a consumer's `Authority` and the token's `iss` diverge and the consumer hasn't set an explicit `ValidIssuer`, validation fails with `IDX10205: Issuer validation failed`. That's the symptom of a misconfigured consumer in a deployment that didn't make the two values match — re-check the proxy / DNS so the auth service is reachable at the canonical hostname.

### 9. Structured logging / SIEM contract


The service emits structured logs via Serilog. In production, point the platform's log aggregator at the container's stdout — output is JSON-line when the `Compact` formatter is active. Every log line carries:

- `RequestId` / `TraceId` — request correlation. When OpenTelemetry tracing lands, `TraceId` is also the join key against trace spans.
- `EventId.Id` and `EventId.Name` — for security-relevant events, taken from `SecurityEventIds`. SIEM rules match on these IDs rather than message strings, so values are stable across deploys.

Security events span four numeric ranges:

| Range | Category | Examples |
|---|---|---|
| 1000s | Authentication | `LoginSucceeded` (1001), `LoginFailed` (1002), `MfaChallengeIssued` (1003), `MfaVerified` (1004), `MfaFailed` (1005), `FailedLoginLockoutTriggered` (1006), `RefreshTokenRotated` (1007), `RefreshTokenReuseDetected` (1008, **Critical**), `LogoutPerDevice` (1009), `LogoutAllDevices` (1010) |
| 2000s | Registration | `RegistrationCompleted` (2001), `EmailConfirmed` (2002), `EmailConfirmationFailed` (2003) |
| 3000s | Account management | `PasswordChanged` (3001), `PasswordResetRequested` (3002), `PasswordResetCompleted` (3003), `AccountLockedByUser` (3004), `MfaEnabled` (3005) |
| 4000s | Token state | `TokenRevoked` (4001), `RevokedTokenReplayAttempt` (4002), `OrphanedTokenRevoked` (4003), `RevokedTokenReplayThresholdWarned` (4004), `RevokedTokenReplayThresholdLocked` (4005, **Critical**) |

**Field-shape contract:**

- `UserId` — always the `sub` claim / `User.Id`. Empty string when the target user doesn't exist (failed login on unknown email).
- `IpAddress` — caller's IP, post-`UseForwardedHeaders` so it's the real client.
- `UserAgent` — auto-attached to every log event during an HTTP request via `HttpContextLogEnricher`. Comes from the request's `User-Agent` header verbatim; absent from worker-emitted events (threshold-escalation worker, data-retention sweep) which have no `HttpContext`.
- `Jti` — access-token jti claim.
- `FamilyId` — refresh-token family / `sid` claim.
- `Reason` — `LoginFailureReason` or `RevocationReasons` value.
- `Provider` — `MfaProviders` enum.
- `Severity` — `Severity` enum (used on revoked-token replay attempts).

PascalCase, same name = same meaning across every event.

**SIEM rules that benefit from `UserAgent`:**
- `EventId = 1001` (LoginSucceeded) `GROUP BY UserId` — flag when a user's typical UA shifts (e.g. Chrome → curl, or browser → Python script). Behavioural signal of credential theft or account-sharing.
- Same `Jti` seen with multiple distinct UAs in a short window — token-sharing or forwarded-credential signal.
- Login UA vs refresh UA diff for the same `FamilyId` — suggests the refresh token left the original device/browser.

**PII posture:**
- `UserId` is logged for forensic correlation.
- **Email addresses, passwords, tokens, refresh-token values, and authenticator secrets are never logged.** If an investigator needs to map `UserId` to email, they go to the auth DB (which has its own retention policy).

**Recommended SIEM detections to wire up first:**
- `EventId = 1008` (RefreshTokenReuseDetected) — page on every occurrence. High-confidence theft signal.
- `EventId = 4005` (RevokedTokenReplayThresholdLocked) — page on every occurrence. The threshold-escalation worker has just locked an account because someone hammered with a stolen access token.
- `EventId = 1002 GROUP BY UserId` with count > N in 60 seconds — credential stuffing against a known user.
- `EventId = 1002 WHERE UserId IS EMPTY GROUP BY IpAddress` — credential scanning against unknown emails from one source.
- `EventId = 1006` (FailedLoginLockoutTriggered) — informational, useful to see in dashboards.
- `EventId = 4002 GROUP BY Jti` with count > 5 — automated replay of a revoked token (the worker handles this for you, but the SIEM rule is a useful belt-and-braces if the worker is disabled).
- `EventId = 4004` (RevokedTokenReplayThresholdWarned) — early-warning bug detection. A misbehaving SPA in a retry loop will fire this against a logged-out user; an attacker will progress past it to 4005 quickly.

### 9a. Threshold escalation on revoked-token replay

The `RevokedTokenReplayEscalationService` background worker watches `RevokedTokenAccessAttempts` for sustained replay of already-revoked tokens. Two thresholds, both within a sliding window:

| Threshold | Default | What happens |
|---|---|---|
| **Warn** | 2 replays in 5 min | Emits `RevokedTokenReplayThresholdWarned` (4004, Warning). No user-facing impact. Useful for spotting buggy clients in retry loops. |
| **Lock** | 5 replays in 5 min | Locks the account indefinitely (`LockoutEnd = MaxValue`), revokes every refresh-token family for the user, rotates the security stamp, emails the user a recovery link. Emits `RevokedTokenReplayThresholdLocked` (4005, Critical). |

Idempotency: each escalation level stamps a column on the `RevokedToken` row (`WarnedAt`, `LockedAt`) so it fires once per incident, not once per sweep.

User recovery follows the standard reset-password flow — see [§9b](#9b-lockout--recovery-contract). The lock-notification email includes a ready-made reset link built from `PublicUrlSettings:BaseUrl` + the reset-password route, so the user doesn't need their app's UI to surface a "forgot password" affordance.

**Tuning** (`ThresholdEscalationSettings` in `appsettings.json`):

| Key | Default | Notes |
|---|---|---|
| `Enabled` | `true` | Master kill switch. Set to `false` during automated load tests where you'd burn through these thresholds artificially. |
| `SweepIntervalInMinutes` | 1 | How often the worker scans the audit table. |
| `WindowInMinutes` | 5 | Sliding-window size used by both thresholds. |
| `WarnThreshold` | 2 | Replays within window that emit the warn-level SIEM event. |
| `LockThreshold` | 5 | Replays within window that lock the account. |

Defaults are aggressive on purpose. Loosen them in deployments where retry-on-old-token churn is expected (e.g. integration tests against a single shared user).

### 9b. Lockout & recovery contract

Three different code paths can lock a user out. **All three converge on the same recovery flow** — `/ResetPassword` page → `POST /api/Account/forgotpassword/reset` → on success, `LockoutEnd` is cleared, the failed-attempt counter is reset, every refresh-token family is revoked, and the user is logged in fresh on next sign-in.

| Lock cause | Trigger | How the user finds out | Recovery |
|---|---|---|---|
| **Failed-login lockout** | N consecutive bad passwords (Identity's `MaxFailedAccessAttempts`, default 3) | Email: "Account locked due to failed attempts" | User starts `/forgotpassword` themselves → email link → `/ResetPassword` |
| **Panic-button lock** | User clicks "wasn't me!" link in the password-changed email (`AccountController.LockAccountAsync`) | The lock email tells them what just happened | User clicks the reset link in the *same* email → `/ResetPassword` |
| **Threshold-escalation lock** (§9a) | Sustained replay of a revoked token | Email: "Suspicious activity, account locked, here's a reset link" | User clicks the link in the lock email → `/ResetPassword` |

Why this matters: the `/ResetPassword` page is generic — it doesn't need to know *why* the user's there, and the controller endpoint behind it (`ResetForgottenPasswordAsync`) clears the lockout regardless of cause. So when a future lockout mechanism is added (e.g. an admin-initiated lock), the recovery story is already wired — emit a reset link in the notification email, point it at `/ResetPassword`, done. **Don't build per-cause recovery pages.**

### 10. Key rotation (when needed)

`EcdsaKeyProvider` loads every `*.pem` in `PrivateKeyDirectory` and publishes them all in JWKS, so multiple keys can co-exist during a rotation overlap. `JWTSettings:ActiveKeyId` (the JWK thumbprint) picks which one signs new tokens.

**Rotation runbook (zero-downtime):**

1. **Stage the new key.** Generate a fresh ES256 PEM (see step 1 of the deployment guide) and drop it into `PrivateKeyDirectory` alongside the existing one. Restart / rolling-restart the auth service. Both keys are now loaded; the JWKS endpoint returns both. **The old key is still active** — `ActiveKeyId` hasn't changed yet, so new tokens are still signed with it. The new key sits idle, advertised but unused.
2. **Wait for consumer JWKS caches to refresh.** JwtBearer's default JWKS cache TTL is 24h. Either wait that out, or — if your rotation needs to be faster — tighten `BackchannelTimeout` / `RefreshInterval` on consumers, or trigger a manual re-fetch by recycling them. Until every consumer has the new key in their cache, the cutover in step 3 will reject tokens at validation.
3. **Cut over.** Set `JWTSettings:ActiveKeyId` to the new key's `kid` and restart. New tokens are now signed with the new key; existing in-flight tokens (signed by the old key) still validate because the old key is still loaded and still in JWKS.
4. **Drain.** Wait at least `JWTSettings:ExpiryInMinutes` (default 5) plus `RefreshTokenExpiryInDays` if you also want refresh tokens issued under the old key to drain, then a small safety margin. After that, no token signed by the old key is still valid.
5. **Decommission the old key.** Remove the old PEM from `PrivateKeyDirectory` and restart. The JWKS endpoint stops advertising it. Move the file to long-term cold storage (or destroy, per your key-management policy) — it should never be possible to re-introduce a retired key by accident.

The `kid` you publish to operations for step 3 is the value visible in the JWKS endpoint's `kid` field (also logged at startup: `Loaded ES256 signing key {KeyId} from '{Path}'`).

Consumers using `Authority`-based JwtBearer auto-refresh JWKS every 24 hours by default, so they pick up new keys without redeployment. Tighten that interval if your rotation cadence is faster than 24 hours.

### 11. Distributed rate limiting

Rate limits are enforced cluster-wide via Redis. With multiple replicas behind a load balancer, every replica's limiter consults the same Redis-backed counters — caps stay constant as you scale replicas up or down.

**Three policies, layered:**

| Policy | Limit (Redis, cluster-wide) | Applied to |
|---|---|---|
| Global default | 4 req / 10s per user (or per IP if anonymous) | Every endpoint as a catch-all |
| `auth-strict` | 10 req / minute per IP | Unauthenticated credential / link endpoints (login, MFA, register, forgot-password, etc.) |
| `auth-sensitive` | 10 req / minute per user | Authenticated state-changing endpoints (change-password, enable-MFA) |
| Health-check carve-out | 30 req / 10s per IP | `/livez`, `/readyz`, `/healthz` — orchestrator probes shouldn't be throttled with API traffic |

The `auth-strict` and `auth-sensitive` policies are applied via `[EnableRateLimiting]` attributes on the controller actions. Most-restrictive across all applicable limiters wins per request.

**In-memory fallback when Redis is down.** The global limiter is *chained* — Redis primary plus an in-memory limiter as fallback. When Redis is up, Redis caps are the binding constraint (tighter, distributed). When Redis goes down, the in-memory fallback (per-replica caps, looser cluster-wide because of the replica multiplier) takes over. Why this matters: the readiness probe pulls a Redis-down replica from the K8s service within ~10-30 seconds, but during that window incoming requests still need *some* protection. The fallback provides it.

The named policies (`auth-strict`, `auth-sensitive`) are Redis-only and fail-open if Redis is down — they vanish until Redis recovers. The global in-memory fallback covers them in degraded mode.

**Operationally:** when Redis is down for an extended period, you'll see `LogWarning` events from the rate limiter and the `RedisHealthCheck` will mark `/readyz` as unhealthy. K8s removes the replica from service. Self-heals when Redis recovers — the next `/readyz` probe passes, K8s adds the replica back, the Redis primary resumes binding.

**Sized for an enterprise platform.** The Redis caps may need tightening or loosening based on actual traffic patterns. The right way to tune them is by watching real `EventId = ...` rate-limit-rejection counts in the SIEM and adjusting against the rejection rate — too-loose means attacks get through; too-tight means legitimate users hit 429s. Defaults shipped here are conservative starting points.

### 12. Email dispatch

Outbound email goes through an **in-memory queue + background dispatcher** rather than blocking the request thread on the SMTP send. Controllers call `_emailService.SendEmailAsync(...)` which writes to a bounded `Channel<T>` and returns immediately (sub-millisecond); a `BackgroundService` reads from the channel and does the actual SMTP work off the request path.

The dispatcher uses MailKit and **holds the SMTP connection open across messages**. Connection reuse + SMTP pipelining (when the server advertises it) means a sustained burst of emails amortises the TLS-handshake / authentication cost across all of them — typically 3-10× the throughput of a fresh-connect-per-send model. The connection is established lazily on the first message and re-established whenever it drops (idle-disconnect from the SMTP server, network blip, etc.). Clean QUIT on shutdown.

**What this changes:**

- Login / registration / forgot-password requests no longer wait for SMTP. A slow or hung SMTP server doesn't stall the auth service's request handling.
- SMTP errors after queueing are logged but **not** propagated back to the controller — by design, a downstream email problem shouldn't fail the user's request mid-flow.

**Failure modes worth knowing:**

| Symptom | What happens | Operator action |
|---|---|---|
| SMTP slow | Queue absorbs the latency; controllers stay fast. Dispatcher catches up when SMTP recovers. | None — system self-heals. |
| SMTP throws on send | Logged at `Error`. Message is dropped. Dispatcher continues with the next message. | Investigate the SMTP server; the user can re-trigger the email by re-running the flow (forgot-password again, etc.). |
| Sustained SMTP outage filling the queue | After ~1000 messages the queue is full. Producers (controllers) wait up to 1 second for space, then log + drop. The controller's request still returns successfully — the user sees "check your inbox" but the email never arrives. | Investigate SMTP. The `LogError` "Email queue full" entries in the logs are the alert signal. |
| Replica restart with messages still in the queue | Anything not yet drained is lost. | None — auth-service email volumes are low enough that this loss window is tiny. If cross-replica persistence is needed for compliance, swap the queue for Hangfire / similar. |

**Per-replica queue.** Each replica has its own in-memory channel and dispatcher. Whichever replica receives the request also dispatches its own emails — meaning the dispatcher must run on every replica that queues, regardless of `HostingSettings:BackgroundWorkersEnabled`. The hosted service is wired in `AddServices` (always-on) rather than the gated `AddHostedServices` bucket (cleanup / escalation workers, which are an unrelated concern).

### 13. Security response headers

Every response carries a small set of security headers as defence-in-depth backstops. Implemented in `SecurityHeadersMiddleware`, applied early in the pipeline (right after `UseStaticFiles()`) so every response — including 404s, static files, and Razor pages — gets them.

| Header | Value | Why |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'`, `script-src 'self' 'unsafe-inline'`, `frame-ancestors 'none'`, etc. | Locks down what scripts / styles / images / iframes the browser will load. Defends against XSS even if a payload reaches our HTML. The Razor pages need `'unsafe-inline'` for now; tighten to nonce-based later if needed. |
| `X-Content-Type-Options` | `nosniff` | Stops the browser overriding our Content-Type. Defends against MIME-confusion attacks. |
| `X-Frame-Options` | `DENY` | Refuses iframe embedding. Defends against clickjacking. Duplicated by CSP `frame-ancestors 'none'` for older browsers. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Caps what gets sent in `Referer` on outbound requests. Stops us leaking URLs (which contain reset-password tokens!) to third-party sites. |
| `Permissions-Policy` | empty allow-lists for `camera`, `microphone`, `geolocation`, `payment`, `usb`, `fullscreen` | Disables browser features the auth service has no business using. Defence in depth. |

`HSTS` is set separately in `WebApplicationExtensions.ConfigureApplicationAsync` (only in non-Development).

---

## Wiring up a consuming microservice

Microservices that need to authenticate users by validating tokens issued here use the **`AuthenticationService.Client`** library. They never see the signing key — they fetch the public key from `/.well-known/jwks.json`.

### 1. Add the project / package reference

```xml
<ProjectReference Include="..\AuthenticationService.Client\AuthenticationService.Client.csproj" />
```

(Once published as a NuGet package, switch to `<PackageReference Include="AuthenticationService.Client" />`.)

### 2. Configure

```jsonc
// appsettings.json
"AuthenticationService": {
  "Authority": "https://auth.example.com",   // base URL of the auth service
  "Issuer": "https://auth.example.com",      // must match JWTSettings.ValidIssuer in the auth service
  "Audience": "platform-api",
  "RequireHttpsMetadata": true
}
```

> **Why both `Authority` *and* `Issuer`?** They're separate concerns that look like the same URL:
>
> - `Authority` is the *network URL* JwtBearer contacts to fetch the OIDC discovery doc and signing keys. It's a routing target.
> - `Issuer` is the *logical name* that must appear in every token's `iss` claim, sourced from `JWTSettings.ValidIssuer` in the auth service. It's an identity, not an address.
>
> In production these are usually the same string (e.g. both `https://auth.example.com` once TLS terminates at a reverse proxy with the canonical hostname). In dev they diverge — the auth service advertises `iss: https://auth.example.com` but actually listens on `https://localhost:53217`, so consumers point `Authority` at the localhost URL while keeping `Issuer` as the canonical name.
>
> Setting both explicitly here makes the consumer work in both environments unchanged. If you ever omit `Issuer`, JwtBearer falls back to deriving it from `Authority` — fine in prod where they match, broken in dev where they don't (you'll see `IDX10205: Issuer validation failed`). Production-deployment §8 has the full story under "`Authority` and `Issuer` — make them match in production".

### 3. Wire it up

```csharp
using AuthenticationService.Client;
using AuthenticationService.Shared.Constants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthenticationServiceJwt(
    builder.Configuration.GetSection("AuthenticationService"));

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(PolicyConstants.AdminOnly, p => p.RequireRole(RolesConstants.Admin));

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
```

That's it. JwtBearer auto-discovers signing keys from `{Authority}/.well-known/openid-configuration`, caches them in memory, and refreshes periodically.

### 4. Protect endpoints

```csharp
using AuthenticationService.Shared.Constants;

[Authorize]                                               // any authenticated user
[Authorize(Policy = PolicyConstants.AdminOnly)]           // admin only
[Authorize(Roles = RolesConstants.Admin)]                 // role-based, equivalent
public class WidgetsController : ControllerBase { ... }
```

### 5. Reading user identity inside endpoints

Standard ASP.NET Core `ClaimsPrincipal`:

```csharp
using AuthenticationService.Shared.Constants;
using System.Security.Claims;

var username = User.Identity?.Name;                          // display name from "name" claim
var isAdmin  = User.IsInRole(RolesConstants.Admin);          // checks "role" claims

var userId   = User.FindFirstValue(ClaimConstants.Sub);      // stable user ID — use this as a foreign key in your DB
var jti      = User.FindFirstValue(ClaimConstants.Jti);      // unique per token; useful for correlation / dedup
var sid      = User.FindFirstValue(ClaimConstants.Sid);      // session/refresh-family ID
var email    = User.FindFirstValue(ClaimConstants.Email);
```

`sub` is the value to persist if you ever need to reference this user from your own data. It never changes; `name` and `email` can.

### Available shared constants

From `AuthenticationService.Shared.Constants` (transitively available via the Client lib reference):

| Class | Members |
|---|---|
| `ClaimConstants` | `Sub`, `Sid`, `Jti`, `Name`, `Email`, `Role`, `Exp` |
| `PolicyConstants` | `AdminOnly` |
| `RolesConstants` | `Admin`, `DefaultUser` (+ `.Normalised.*`) |
| `AuthSchemeConstants` | `Bearer`, `BearerPrefix` |

Use these instead of magic strings — both sides of the wire stay in sync by construction.

---

## How tokens are validated (under the hood)

```
Microservice startup
  │
  └─ AddAuthenticationServiceJwt
        │
        └─ JwtBearer fetches:
             https://auth.example.com/.well-known/openid-configuration
                 ↓
             https://auth.example.com/.well-known/jwks.json
                 ↓
             Caches public EC key in memory (~24h refresh)

Request arrives with Authorization: Bearer eyJ...
  │
  ├─ JwtBearer reads kid from token header
  ├─ Looks up matching public key in cache
  ├─ Verifies ES256 signature
  ├─ Validates iss, aud, exp
  └─ Populates HttpContext.User and continues to [Authorize]
```

No shared secrets. The auth service is the only thing holding the private key.

### Claim shape

Issued access tokens carry the following claims (consumers can rely on all of these being present):

| Claim | Source | Notes |
|---|---|---|
| `sub` | `User.Id` (GUID) | **Stable user ID.** Use this as a foreign key in consumer databases — `name` and `email` can change. |
| `sid` | `RefreshToken.FamilyId` | Session/refresh-family ID. Persists across rotations within one login session. Used internally for per-device logout. |
| `jti` | New GUID per token | Unique per access token. Used by the deny-list and for correlation. |
| `name` | `User.UserName` | Display name. Mapped to `User.Identity.Name` for `ClaimsPrincipal`. |
| `email` | `User.Email` | Email address. |
| `role` | (multi-value) | One claim per role assignment. Mapped to `ClaimsPrincipal.IsInRole`. |
| `iss` | `JWTSettings.ValidIssuer` | Validated by JwtBearer. |
| `aud` | `JWTSettings.ValidAudience` | Validated by JwtBearer. |
| `exp` | issue time + `JWTSettings.ExpiryInMinutes` | Validated by JwtBearer. |

---

## Open items / future work

- **Service-to-service tokens (client credentials).** Currently consumers forward the user's JWT for downstream calls. A "service identity" flow (each service authenticates to get its own token) is on the roadmap but not implemented.
- **Cross-service revocation latency.** Refresh-token revocation (logout, password change, reuse detection) is instant — the next refresh fails. Access-token revocation has a window equal to the access-token TTL (5 min): the auth service's deny-list catches replays at its own ingress, but other microservices accept tokens until natural `exp`. Acceptable for a 5-min TTL; if instant cross-service revocation is needed, add a token-introspection endpoint or pub/sub.
- **Phone MFA: SMS provider not configured.** The MFA flow understands `Phone` as an option, but the default `ISmsService` registration (`NotConfiguredSmsService`) reports `IsConfigured = false` and the endpoints return a clean `BadRequest` if the user picks Phone. To enable it, implement `ISmsService` against your SMS provider (Twilio, AWS SNS, MessageBird, etc.) and replace the registration in `HostExtensions.AddServices` — no controller changes needed. A phone-number confirmation flow (mirror of the email-confirmation flow) also needs building before phone MFA is usable end-to-end.

---

## Useful endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/Registration/register` | None | Create account |
| `GET /api/Registration/confirm/email` | None | Confirm email via the link sent at registration |
| `POST /api/Registration/confirm/email` | None | Resend the confirmation email |
| `POST /api/Authentication/authenticate` | None | Login (returns token or "MFA required") |
| `POST /api/Authentication/mfa` | None | Submit MFA code, receive token |
| `POST /api/Authentication/refresh` | Expired bearer + refresh body | Rotate to a new pair. Reuse of a consumed refresh token revokes every session for the user (cascade). |
| `POST /api/Authentication/logout` | Bearer | Revoke this device's session. Other devices keep working. |
| `POST /api/Authentication/logoutall` | Bearer | Revoke every session for the user + rotate the security stamp. |
| `POST /api/Account/forgotpassword` | None | Request a password-reset email. Also clears any active lockout on successful reset. |
| `POST /api/Account/forgotpassword/reset` | None | Apply the reset using the email-link token. |
| `GET /api/Account/me` | Bearer | Current user's profile + roles, read live from the DB. Useful for SPA UI rendering and as a "is my token still good?" diagnostic. |
| `POST /api/Account/changepassword` | Bearer | Change password while authenticated. Identity is read from the token's `sub`. |
| `GET /api/Account/enablemfa` | Bearer | Begin MFA enrolment; returns a QR code for the authenticator app. |
| `POST /api/Account/lock` | Email-link token | Triggered from the "wasn't you?" link in password-changed emails — locks the account and sends a reset link. |
| `GET /.well-known/openid-configuration` | None | OIDC discovery doc |
| `GET /.well-known/jwks.json` | None | Public signing keys |
| `GET /api/Test` | Admin | Smoke test (admin policy) |
| `GET /api/Test/all` | Authenticated | Smoke test (any user) |
