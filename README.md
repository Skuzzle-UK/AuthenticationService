# AuthenticationService

Centralised identity & access service for the platform. Issues short-lived ES256-signed
JWTs and exposes a JWKS endpoint so consuming microservices can validate them without
sharing secrets.

---

## Solution layout

| Project | Purpose |
|---|---|
| `AuthenticationService` | The HTTP API: registration, login, MFA, refresh (with rotation + reuse detection), per-device & all-device logout, password reset (which is also the account-unlock path), JWKS/OIDC discovery. |
| `AuthenticationService.Shared` | DTOs, view models, and wire-contract constants (claim names, role values, policy names, auth scheme). Shared between the API, the client library, and any non-.NET clients (mobile, frontend, etc). |
| `AuthenticationService.Client` | The drop-in NuGet/project reference for **other microservices** that need to validate tokens. Provides `AddAuthenticationServiceJwt(...)` and brings `AuthenticationService.Shared` in transitively so consumers get the constants without an extra reference. |
| `ExampleConsumer` | A small minimal-API microservice that demonstrates the client library end-to-end. Useful as a smoke test and as a copy-paste starting point for new services. See [Try it end-to-end](#try-it-end-to-end). |

---

## User flow (end-user perspective)

1. **Register** with email + password.
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

```bash
dotnet run --project AuthenticationService
```

On the first run you should see:

```
warn: AuthenticationService.Services.EcdsaKeyProvider[0]
      No signing key found at 'keys/jwt-signing.pem'. Generating a new ES256 key
      for Development. DO NOT use this key in production.
info: ...
      Application started. Listening on: https://localhost:53217
```

A new `keys/jwt-signing.pem` is created next to the project. **It is gitignored**; do not commit it. Each developer gets their own local key — tokens you issue locally only validate against your own auth service.

If you ever want to invalidate every dev token, delete the file and restart. Tokens expire in 5 minutes anyway.

Database migrations run automatically on startup (`app.RunMigrations()`).

### 4. Seeded admin account

A default admin is seeded on first run. Credentials come from `AdminAccountSeedSettings` in config:

| Field | Default in `appsettings.json` |
|---|---|
| Email | `email@email.com` |
| Password | `Pa5$word123` |
| First name | `Administrator` |
| Country | `United Kingdom` |

**Change the password via user-secrets before exposing the service to anyone.**

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

### What's actually happening

When you start the consumer:

1. JwtBearer hits `https://localhost:53217/.well-known/openid-configuration`.
2. The discovery doc points at `https://localhost:53217/.well-known/jwks.json` and declares `issuer = https://auth.example.com`.
3. JwtBearer fetches the JWK, caches it, and uses it to validate every incoming token's signature against the `kid` in the token header.
4. It also checks `iss == https://auth.example.com`, `aud == platform-api`, and `exp > now`.

> **Common gotcha:** if the consumer's `Authority` setting points at the wrong port, OIDC discovery silently fails — JwtBearer catches the connection error and carries on with no signing keys. The result is a `401` with `"The signature key was not found"` on every request, even with a perfectly valid token. Always verify that `Authority` in `ExampleConsumer/appsettings.json` (and in any new consumer service) matches the port reported by the auth service's `launchSettings.json` (`AuthenticationService/Properties/launchSettings.json`). The `Issuer` value must also match `JWTSettings.ValidIssuer` in the auth service's `appsettings.json`.

There is **no shared secret** between the two services. The consumer never sees the signing key.

---

## Configuration reference

All settings are bound from `appsettings.json` and validated at startup.

### `JWTSettings`

| Key | Description |
|---|---|
| `PrivateKeyPath` | Path to the ECDSA private key in PEM format. Relative paths resolve against the content root. **Must exist in non-Development environments** (no auto-generation). |
| `KeyId` | `"auto"` (default) computes the JWK thumbprint of the public point. Override with a fixed string only if you have a specific `kid` rotation strategy. |
| `ValidIssuer` | Stamped into the `iss` claim. Consumers validate against this. |
| `ValidAudience` | Stamped into the `aud` claim. Currently `"platform-api"` — every consuming microservice must use the same value. |
| `ExpiryInMinutes` | Access token TTL. Short by design. |
| `RefreshTokenExpiryInDays` | Refresh token TTL. |

### `AdminAccountSeedSettings`

Seeds a single admin user on first startup. All fields except `LastName`/`PhoneNumber`/`PhoneNumberConfirmed` are required.

### `EmailServerSettings`

SMTP credentials for outbound email (registration confirmation, MFA, recovery, lockout notices).

### `DataRetentionSettings`

Controls the `DataRetentionService` background sweep that prunes expired audit + token rows.

| Key | Description |
|---|---|
| `CleanupIntervalInHours` | How often the sweep runs. Default 12. |
| `AccessRecordsTTLInDays` | How long `AccessRecord` audit rows are retained after creation. Default 90. `RevokedTokens` and `RefreshTokens` are pruned by their own natural `ExpiresAt`, no separate TTL. |

### `DataProtectionSettings`

ASP.NET Core's data-protection key ring is persisted to Redis (required) and optionally protected by a certificate. Identity tokens (password reset, email confirmation, MFA, lockout) are signed with this ring — without persistence, every replica restart invalidates outstanding email-link tokens.

| Key | Description |
|---|---|
| `RedisKey` | Hash key under which the data-protection keys are stored. Default `"AuthService:DataProtectionKeys"`. Must be unique per app sharing a Redis instance. |
| `ApplicationName` | Data-protection isolation name. Replicas of this service must share it; different apps must not. **Do not change once deployed** — invalidates all outstanding Identity tokens. |
| `Certificate.PfxPath` | (Optional) Path to a PFX file containing the cert + private key used to encrypt the key ring at rest. When absent, keys sit in Redis as readable XML — acceptable on a controlled network during initial rollout, but should be populated before the service is exposed broadly. |
| `Certificate.PfxPassword` | (Optional) Password for the PFX. |

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

The app just reads a file at the configured `PrivateKeyPath`. Pick whichever delivery mechanism your platform offers:

- **Docker:** `-v /host/secrets/jwt-signing.pem:/app/keys/jwt-signing.pem:ro`
- **Docker Compose secrets:** mount at `/run/secrets/jwt-signing` and set `JWTSettings__PrivateKeyPath=/run/secrets/jwt-signing`.
- **Kubernetes:** create a `Secret` containing the PEM, mount it as a file via `volumes` + `volumeMounts`.
- **Azure / AWS:** Key Vault / Secrets Manager → init-container or sidecar writes it to a `tmpfs` volume the app reads.

If the file is missing in non-Development environments the service refuses to start with a clear error.

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
JWTSettings__PrivateKeyPath=/run/secrets/jwt-signing
JWTSettings__ValidIssuer=https://auth.example.com
JWTSettings__ValidAudience=platform-api
ConnectionStrings__MySQL=server=...
ConnectionStrings__Redis=redis.internal:6379
AdminAccountSeedSettings__Password=<one-time-bootstrap-password>
EmailServerSettings__Password=<smtp-secret>
DataProtectionSettings__Certificate__PfxPath=/run/secrets/data-protection.pfx
DataProtectionSettings__Certificate__PfxPassword=<from-secret-store>
ForwardedHeadersSettings__KnownNetworks__0=10.0.0.0/8
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

### 8. HTTPS / hostname

Production must be HTTPS. Consumers configured with `RequireHttpsMetadata = true` (the default) will refuse to fetch JWKS over HTTP.

The **public hostname of the auth service is the contract** — this is the `Authority` URL every consuming microservice points at. Pick it deliberately and avoid changing it (e.g. `https://auth.example.com`, not the load-balancer's hostname).

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
| 4000s | Token state | `TokenRevoked` (4001), `RevokedTokenReplayAttempt` (4002) |

**Field-shape contract:**

- `UserId` — always the `sub` claim / `User.Id`. Empty string when the target user doesn't exist (failed login on unknown email).
- `IpAddress` — caller's IP, post-`UseForwardedHeaders` so it's the real client.
- `Jti` — access-token jti claim.
- `FamilyId` — refresh-token family / `sid` claim.
- `Reason` — `LoginFailureReason` or `RevocationReasons` value.
- `Provider` — `MfaProviders` enum.
- `Severity` — `Severity` enum (used on revoked-token replay attempts).

PascalCase, same name = same meaning across every event.

**PII posture:**
- `UserId` is logged for forensic correlation.
- **Email addresses, passwords, tokens, refresh-token values, and authenticator secrets are never logged.** If an investigator needs to map `UserId` to email, they go to the auth DB (which has its own retention policy).

**Recommended SIEM detections to wire up first:**
- `EventId = 1008` (RefreshTokenReuseDetected) — page on every occurrence. High-confidence theft signal.
- `EventId = 1002 GROUP BY UserId` with count > N in 60 seconds — credential stuffing against a known user.
- `EventId = 1002 WHERE UserId IS EMPTY GROUP BY IpAddress` — credential scanning against unknown emails from one source.
- `EventId = 1006` (FailedLoginLockoutTriggered) — informational, useful to see in dashboards.
- `EventId = 4002 GROUP BY Jti` with count > 5 — automated replay of a revoked token.

### 10. Key rotation (when needed)

The current implementation serves a single key. To rotate:

1. Generate a new keypair.
2. Modify `EcdsaKeyProvider` to load both old + new and publish both in the JWKS response.
3. Sign new tokens with the new key (set its `kid` as the active one).
4. After all old tokens have expired (5 minutes + safety margin), drop the old key.

Consumers using `Authority`-based JwtBearer auto-refresh JWKS every 24 hours by default, so they pick up new keys without redeployment. Tighten that interval if your rotation cadence is faster.

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

> **`Authority` vs `Issuer`:** `Authority` is the URL JwtBearer contacts to fetch the OIDC discovery doc and signing keys. `Issuer` is the string value that must appear in the `iss` claim of every token — it comes from `JWTSettings.ValidIssuer` in the auth service's `appsettings.json`. In production these are typically the same URL, but in development the auth service may advertise a canonical issuer URL (`https://auth.example.com`) while actually running on `https://localhost:53217`. Both fields must be set correctly or token validation will fail.

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
- **Key rotation tooling.** The `EcdsaKeyProvider` serves one key; rotation requires a code change. Consider implementing dual-key support before first production rotation.
- **Cross-service revocation latency.** Refresh-token revocation (logout, password change, reuse detection) is instant — the next refresh fails. Access-token revocation has a window equal to the access-token TTL (5 min): the auth service's deny-list catches replays at its own ingress, but other microservices accept tokens until natural `exp`. Acceptable for a 5-min TTL; if instant cross-service revocation is needed, add a token-introspection endpoint or pub/sub.
- **Threshold escalation on revoked-token replay.** Today a stolen access token replayed against the deny-list returns 401 and writes an `AccessRecord` row, but nothing escalates if the same `jti` is hammered repeatedly. Tracked as a TODO; pairs with the SIEM-forwarding story.

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
| `POST /api/Account/changepassword` | Bearer | Change password while authenticated. Identity is read from the token's `sub`. |
| `GET /api/Account/enablemfa` | Bearer | Begin MFA enrolment; returns a QR code for the authenticator app. |
| `POST /api/Account/lock` | Email-link token | Triggered from the "wasn't you?" link in password-changed emails — locks the account and sends a reset link. |
| `GET /.well-known/openid-configuration` | None | OIDC discovery doc |
| `GET /.well-known/jwks.json` | None | Public signing keys |
| `GET /api/Test` | Admin | Smoke test (admin policy) |
| `GET /api/Test/all` | Authenticated | Smoke test (any user) |
