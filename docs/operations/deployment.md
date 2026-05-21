# Production deployment

End-to-end checklist for getting the auth service into a real environment. Aspire is dev-only — production runs the service as a normal .NET process with operator-supplied infrastructure connection strings.

## 1. Generate the signing key

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

**Treat this file like a database password.** Anyone holding it can mint valid tokens. For routine rotation see [key-rotation.md](key-rotation.md).

## 2. Inject the key

The app reads every `*.pem` file in the configured `PrivateKeyDirectory`. Pick whichever delivery mechanism your platform offers — the directory mount + file naming is the only contract:

- **Docker:** `-v /host/secrets/auth-keys:/app/keys:ro`
- **Docker Compose secrets:** mount each PEM under `/run/secrets/` and project them into `/app/keys/` via a tmpfs.
- **Kubernetes:** create a `Secret` containing one or more PEM keys, mount it as a directory via `volumes` + `volumeMounts.mountPath`.
- **Azure / AWS:** Key Vault / Secrets Manager → init-container writes each PEM into a shared `tmpfs` volume the app reads.

If the directory is empty in non-Development environments the service refuses to start with a clear error. The filename itself is irrelevant — the `kid` is computed from the public-key thumbprint, not the filename.

## 3. Provision Redis

The data-protection key ring is persisted to Redis. **Without it, the service will refuse to start.** Two things matter for the deploy:

- **Reachability.** Set `ConnectionStrings__Redis` to whatever the platform's Redis endpoint is (host:port, or full StackExchange.Redis connection string for clustered/auth'd setups).
- **Persistence.** Confirm with the platform team that the Redis instance has AOF or RDB persistence enabled. If it's a pure-cache Redis that gets wiped on restart, every outstanding email-link token (password reset, email confirmation, MFA codes, lockout links) breaks whenever Redis restarts. Most production Redis has persistence on, but explicitly confirm.

If the Redis is shared with other apps, `DataProtectionSettings:RedisKey` and `ApplicationName` together provide isolation — keep them unique per app.

## 4. Configure data-protection at-rest encryption (recommended)

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

## 5. Configure forwarded headers (if behind a proxy)

If the service is deployed behind a load balancer / reverse proxy / ingress (which it almost certainly is in any corporate setup), populate `ForwardedHeadersSettings` with the proxy's network range. Without this, every audit IP recorded will be the LB's address rather than the real client.

```bash
ForwardedHeadersSettings__KnownNetworks__0=10.0.0.0/8
ForwardedHeadersSettings__KnownProxies__0=203.0.113.10
```

(Either of `KnownNetworks` or `KnownProxies` is fine; usually you'd populate `KnownNetworks` with the LB subnet.)

The middleware also uses `X-Forwarded-Proto` to detect TLS-terminated-at-the-LB deployments. Without it, `app.UseHttpsRedirection()` would loop because the app sees an HTTP connection from the LB and tries to redirect to HTTPS, which the LB receives back and forwards as HTTP again.

## 6. Override config via environment variables

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

For the full settings surface see [reference/configuration.md](../reference/configuration.md).

## 7. Database migrations

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

## 7a. Split API + worker deployments (multi-replica)

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

## 8. HTTPS / hostname

Production must be HTTPS. Consumers configured with `RequireHttpsMetadata = true` (the default) will refuse to fetch JWKS over HTTP.

The **public hostname of the auth service is the contract** — this is the `Authority` URL every consuming microservice points at. Pick it deliberately and avoid changing it (e.g. `https://auth.example.com`, not the load-balancer's hostname).

### `Authority` and `Issuer` — make them match in production

The auth service has two distinct settings that *look* similar:

- **`JWTSettings.ValidIssuer`** — a *logical name* stamped into every token's `iss` claim. Consumers validate `iss` against this string. It's an identity, not an address.
- **`Authority`** (consumer-side) — the *network URL* where consumers fetch the JWKS / OIDC discovery doc. It's a routing target.

In dev these diverge: `ValidIssuer` is `https://auth.example.com` (a stable logical name), but consumers point `Authority` at `https://localhost:53217` (where the auth service actually runs). The `ExampleConsumer` config explicitly sets *both* `Authority` and `Issuer` so the divergence works — JwtBearer fetches keys from one URL and validates `iss` against the other.

**In production, terminate TLS at a reverse proxy / load balancer with the canonical hostname that matches `JWTSettings.ValidIssuer`.** Once the network URL and the logical issuer are the same string (e.g. both `https://auth.example.com`), JwtBearer's defaults Just Work and consumers no longer need to override `ValidIssuer` separately — they can just set `Authority` and let the issuer be inferred from the discovery doc.

If a consumer's `Authority` and the token's `iss` diverge and the consumer hasn't set an explicit `ValidIssuer`, validation fails with `IDX10205: Issuer validation failed`. That's the symptom of a misconfigured consumer in a deployment that didn't make the two values match — re-check the proxy / DNS so the auth service is reachable at the canonical hostname.

## See also

- [operations/key-rotation.md](key-rotation.md) — zero-downtime signing-key rotation runbook
- [operations/observability.md](observability.md) — OpenTelemetry wiring + SIEM contract
- [operations/runbook.md](runbook.md) — incident response (placeholder until operationally exercised)
- [reference/configuration.md](../reference/configuration.md) — complete settings reference
