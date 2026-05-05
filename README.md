# AuthenticationService

Centralised identity & access service for the platform. Issues short-lived ES256-signed
JWTs and exposes a JWKS endpoint so consuming microservices can validate them without
sharing secrets.

---

## Solution layout

| Project | Purpose |
|---|---|
| `AuthenticationService` | The HTTP API: registration, login, MFA, refresh, account recovery, JWKS/OIDC discovery. |
| `AuthenticationService.Shared` | DTOs and view models shared between the API and any non-.NET clients (mobile, frontend, etc). |
| `AuthenticationService.Client` | The drop-in NuGet/project reference for **other microservices** that need to validate tokens. Provides `AddAuthenticationServiceJwt(...)` plus the shared policy/role/scheme constants. |
| `ExampleConsumer` | A small minimal-API microservice that demonstrates the client library end-to-end. Useful as a smoke test and as a copy-paste starting point for new services. See [Try it end-to-end](#try-it-end-to-end). |

---

## User flow (end-user perspective)

1. **Register** with email + password.
2. **Confirm email** via the link sent to the inbox.
3. **Authenticate** with email/username + password — receive a JWT (5 min) + refresh token (5 days).
4. (Optional) **Enable MFA** — server returns a QR code.
5. With MFA enabled: authenticate with credentials → server returns "MFA required" → submit MFA code → receive token.
6. **Refresh** before expiry using the refresh token.
7. **Logout** revokes the access token's `jti` (denylist held in the auth service DB).

---

## Prerequisites

- **.NET 10 SDK**
- **MySQL 8** (any reachable instance — local, container, or managed)
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
| `GET /me` | Authenticated | Returns the caller's identity (name, roles, jti) from the validated token. |
| `GET /admin` | Admin role | Restricted to tokens whose `role` claim contains `Admin`. |

### Walk-through

1. Open `https://localhost:53217/swagger` (the **auth service**) and call `POST /api/Authentication/authenticate` with the seeded admin creds. Copy `token.value` from the response.
2. Open `https://localhost:50500/swagger` (the **example consumer**).
3. Click **Authorize**, paste the token, Authorize, Close.
4. Call `GET /me` → 200 with your username, roles `["DefaultUser","Admin"]`, and the `jti`.
5. Call `GET /admin` → 200 (because your token carries the `Admin` role).
6. Call `GET /` → 200 anonymously, no token needed.

### Negative tests worth running

- **Tamper with the token.** Change one character in the middle of the JWT and retry — `/me` returns 401 because the signature no longer verifies.
- **Wait > 5 minutes**, then retry — 401, expired (`exp` claim).
- **Stop the auth service before the consumer starts** — the consumer fails fast at startup (can't reach the discovery endpoint).
- **Restart the auth service so a new dev key is generated** — old tokens stop validating; the consumer auto-picks up the new JWKS at next refresh.

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

### `RevokedTokenSettings`

| Key | Description |
|---|---|
| `CleanupIntervalInMinutes` | How often the background hosted service prunes expired entries from the revoked-token / access-record tables. |
| `AccessRecordsTTLInDays` | How long access records are retained. |

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

### 3. Override config via environment variables

ASP.NET Core's standard double-underscore mapping applies:

```bash
JWTSettings__PrivateKeyPath=/run/secrets/jwt-signing
JWTSettings__ValidIssuer=https://auth.example.com
JWTSettings__ValidAudience=platform-api
ConnectionStrings__MySQL=server=...
AdminAccountSeedSettings__Password=<one-time-bootstrap-password>
EmailServerSettings__Password=<smtp-secret>
```

### 4. Database migrations

Migrations run automatically at startup. If you'd rather run them out-of-band:

```bash
cd AuthenticationService
dotnet ef database update
```

### 5. HTTPS / hostname

Production must be HTTPS. Consumers configured with `RequireHttpsMetadata = true` (the default) will refuse to fetch JWKS over HTTP.

The **public hostname of the auth service is the contract** — this is the `Authority` URL every consuming microservice points at. Pick it deliberately and avoid changing it (e.g. `https://auth.example.com`, not the load-balancer's hostname).

### 6. Key rotation (when needed)

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
using AuthenticationService.Client.Constants;

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
using AuthenticationService.Client.Constants;

[Authorize]                                               // any authenticated user
[Authorize(Policy = PolicyConstants.AdminOnly)]           // admin only
[Authorize(Roles = RolesConstants.Admin)]                 // role-based, equivalent
public class WidgetsController : ControllerBase { ... }
```

### 5. Reading user identity inside endpoints

Standard ASP.NET Core `ClaimsPrincipal`:

```csharp
var username = User.Identity?.Name;
var isAdmin  = User.IsInRole(RolesConstants.Admin);
var jti      = User.FindFirstValue("jti");   // useful for correlation / logging
```

### Available shared constants

From `AuthenticationService.Client.Constants`:

| Class | Members |
|---|---|
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

---

## Open items / future work

- **Service-to-service tokens (client credentials).** Currently consumers forward the user's JWT for downstream calls. A "service identity" flow (each service authenticates to get its own token) is on the roadmap but not implemented.
- **Key rotation tooling.** The `EcdsaKeyProvider` serves one key; rotation requires a code change. Consider implementing dual-key support before first production rotation.
- **Cross-service revocation.** `IsRevokedAsync` checks the auth service's DB. Other services can't see revocations — they accept tokens until expiry (5 min). For instant cross-service revocation, add an introspection endpoint or pub/sub.

---

## Useful endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/Registration/register` | None | Create account |
| `POST /api/Authentication/authenticate` | None | Login (returns token or "MFA required") |
| `POST /api/Authentication/mfa` | None | Submit MFA code, receive token |
| `POST /api/Authentication/refresh` | Expired bearer + refresh body | Get a new token pair |
| `GET /api/Authentication/logout` | Bearer | Revoke current token |
| `GET /.well-known/openid-configuration` | None | OIDC discovery doc |
| `GET /.well-known/jwks.json` | None | Public signing keys |
| `GET /api/Test` | Admin | Smoke test (admin policy) |
| `GET /api/Test/all` | Authenticated | Smoke test (any user) |
