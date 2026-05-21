# Getting started

Fastest path from a fresh clone to a running auth service + a consumer microservice that trusts its tokens. Should take ~10 minutes including image pulls.

## Prerequisites

- **.NET 10 SDK**
- **Docker** (or a Docker-compatible runtime — Rancher Desktop / Podman Desktop). Aspire uses this to spin up MySQL / Redis / smtp4dev / Grafana as containers for local dev.
- (Optional) **Visual Studio 2026 / Rider** if you want the F5 → Aspire dashboard flow.

If you want to run *without* Aspire (you supply your own MySQL / Redis / SMTP), you'll need:

- **MySQL 8** (local, container, or managed)
- **Redis** for data-protection key persistence (e.g. `docker run -d -p 6379:6379 redis:alpine`)
- An **SMTP relay** for outbound email — [Papercut SMTP](https://github.com/ChangemakerStudios/Papercut-SMTP) or MailHog for local dev

## 1. Clone and restore

```bash
git clone <repo-url>
cd AuthenticationService
dotnet restore
```

## 2. Configure local secrets

The default `appsettings.json` ships with placeholder values that are **safe enough for first-run** but should be overridden via [User Secrets](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets) for anything sensitive:

```bash
cd AuthenticationService
dotnet user-secrets set "ConnectionStrings:MySQL" "server=localhost;port=3306;database=AuthenticationService;user=root;password=<your-password>;"
dotnet user-secrets set "AdminAccountSeedSettings:Password" "<your-strong-password>"
dotnet user-secrets set "EmailServerSettings:Password" "<smtp-password>"
```

Anything you don't override falls back to the values in `appsettings.json` / `appsettings.Development.json`. The dev-default admin password (`Pa5$word123`) is fine for local-only and is rejected verbatim outside Development.

## 3. Run

**Option A — via .NET Aspire (recommended).** Auto-spins MySQL, Redis, smtp4dev, and the Grafana / OTel observability stack as containers:

```bash
dotnet run --project AuthenticationService.AppHost
```

Or in Visual Studio: set `AuthenticationService.AppHost` as the startup project and F5. Aspire pulls / starts the containers, injects connection strings, then launches the auth service as a normal .NET process (debugger attaches normally; no container indirection). The Aspire dashboard opens in a browser showing live logs, traces, metrics, and clickable links into each container's web UI (e.g. smtp4dev's inbox at the http endpoint shown on the dashboard's `smtp4dev` resource).

**Option B — directly** (you supply MySQL / Redis / SMTP yourself):

```bash
dotnet run --project AuthenticationService
```

> **Production deploys do NOT use Aspire.** The auth service ships on its own with operator-supplied infrastructure connection strings. See [operations/deployment.md](operations/deployment.md).

On the first run you should see:

```
warn: AuthenticationService.Services.EcdsaKeyProvider[0]
      No signing keys found in 'keys'. Generating a new ES256 key for Development.
      DO NOT use this key in production.
info: ...
      Application started. Listening on: https://localhost:53217
```

A new `keys/jwt-signing.pem` is created next to the project. **The whole `keys/` directory is gitignored**; do not commit it. Each developer gets their own local key — tokens you issue locally only validate against your own auth service. To invalidate every dev token, delete the directory contents and restart. Tokens expire in 5 minutes anyway.

Database migrations run automatically on startup in Development (`app.RunMigrations()`).

## 4. Seeded admin account

A default admin is seeded on first run. Most fields come from `appsettings.json`:

| Field | Default | Source |
|---|---|---|
| Email | `email@email.com` | `appsettings.json` |
| First name | `Administrator` | `appsettings.json` |
| Country | `United Kingdom` | `appsettings.json` |
| **Password** | `Pa5$word123` | **`appsettings.Development.json` (dev only)** |

The password lives in `appsettings.Development.json` deliberately so `dotnet run` works first time without anyone having to think about credentials. **Outside Development the service refuses to start unless `AdminAccountSeedSettings:Password` is supplied via env var, user-secrets, or a secret store** — and it rejects the dev default verbatim, so a copy-pasted dev config can't accidentally reach prod. See [operations/deployment.md](operations/deployment.md) for the override mechanism.

## 5. Try it via Swagger

Hit `https://localhost:<port>/swagger`.

1. Call `POST /api/Authentication/authenticate` with the seeded admin credentials.
2. Copy the `token.value` field from the response.
3. Click the **Authorize** button (top right), paste the token (no `Bearer ` prefix), Authorize, Close.
4. Call `GET /api/Test` — should return 200 with `"Test succeeded"`.

## 6. End-to-end with `ExampleConsumer`

The `ExampleConsumer` project simulates a separate microservice that trusts tokens issued by `AuthenticationService`. It validates them by fetching the JWKS — no shared secrets, no extra config.

### Run both services

In two terminals (or via VS multi-startup):

```bash
# Terminal 1
dotnet run --project AuthenticationService    # https://localhost:53217

# Terminal 2
dotnet run --project ExampleConsumer          # https://localhost:50500
```

The consumer's Swagger lives at `https://localhost:50500/swagger`. Five endpoints:

| Endpoint | Auth | Behaviour |
|---|---|---|
| `GET /` | Anonymous | Returns a hello message. |
| `GET /me` | Authenticated | Returns the caller's identity from the validated token. |
| `GET /admin` | Admin role | Restricted to tokens whose `role` claim contains `Admin`. |
| `GET /example-read` | Scope `example.read` | Service-to-service demo — see [consumers/outgoing-service-tokens.md](consumers/outgoing-service-tokens.md). |
| `POST /example-write` | Scope `example.write` | Same shape, `example.write` scope. |

### Walk-through

1. Open `https://localhost:53217/swagger` (the **auth service**) and call `POST /api/Authentication/authenticate` with the seeded admin creds. Copy `token.value` from the response.
2. Open `https://localhost:50500/swagger` (the **example consumer**).
3. Click **Authorize**, paste the token, Authorize, Close.
4. Call `GET /me` → 200 with your username, roles `["DefaultUser","Admin"]`, the `jti`, and the `sub`.
5. Call `GET /admin` → 200 (your token carries the `Admin` role).
6. Call `GET /` → 200 anonymously, no token needed.

### Negative tests worth running

- **Tamper with the token.** Change one character mid-JWT and retry — `/me` returns 401 (signature won't verify).
- **Wait > 5 minutes**, then retry — 401, expired (`exp` claim).
- **Stop the auth service before the consumer starts** — the consumer fails fast at startup (can't reach the discovery endpoint).
- **Restart the auth service so a new dev key is generated** — old tokens stop validating; the consumer auto-picks up the new JWKS at next refresh.
- **Replay a consumed refresh token.** Authenticate, hit `/refresh` once successfully, then hit `/refresh` again with the *original* (now-consumed) refresh token. Expect 401, plus a full-cascade revocation across every session family. See [concepts/refresh-rotation.md](concepts/refresh-rotation.md).
- **Per-device logout isolation.** Log in twice with the same admin (two browser sessions). Hit `/logout` from one — the other should keep working until you also `/logout` it.
- **Restart the auth service WITHOUT restarting Redis.** Outstanding email-link tokens (password reset, email confirmation) should still work — proof that the data-protection key ring survived restart via Redis persistence.
- **Try registering with a reserved username.** `POST /api/Registration/register` with `{ "UserName": "Administrator", ... }` returns 400 with `errors.ReservedUserName`.
- **Replay a consumed email-confirmation link.** Click the confirmation link, then click it again — fails because the security stamp rotated on the first confirm.

## Next steps

- **Wiring a new consumer service** → [consumers/validating-incoming-tokens.md](consumers/validating-incoming-tokens.md)
- **Service-to-service calls** → [consumers/outgoing-service-tokens.md](consumers/outgoing-service-tokens.md)
- **Architecture overview** → [architecture.md](architecture.md)
- **Running tests** → [development/testing.md](development/testing.md)
- **Deploying to production** → [operations/deployment.md](operations/deployment.md)
