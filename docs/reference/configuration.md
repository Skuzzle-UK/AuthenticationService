# Configuration reference

All settings are bound from `appsettings.json` and validated at startup. Env-var overrides use ASP.NET Core's standard double-underscore mapping (e.g. `JWTSettings__ValidIssuer`).

## `JWTSettings`

| Key | Description |
|---|---|
| `PrivateKeyDirectory` | Directory containing one or more ECDSA private keys in PEM format (`*.pem`). Relative paths resolve against the content root. Every key in the directory is loaded; all are published in the JWKS so consumers can validate tokens signed by any of them. **Must contain at least one key in non-Development environments** (no auto-generation). In Development, an empty directory triggers a one-time auto-generated key so `dotnet run` works first time. |
| `ActiveKeyId` | The `kid` (JWK thumbprint) of the key used to sign newly-issued tokens. `"auto"` (default) picks the first key found — fine for single-key operation; set explicitly during a rotation cutover so the active signer is unambiguous. See [operations/key-rotation.md](../operations/key-rotation.md). |
| `ValidIssuer` | Stamped into the `iss` claim. Consumers validate against this. |
| `ValidAudience` | Stamped into the `aud` claim. Currently `"platform-api"` — every consuming microservice must use the same value. |
| `ExpiryInMinutes` | Access token TTL. Short by design (default 5). |
| `RefreshTokenExpiryInDays` | Refresh token TTL (default 5). |

## `ClientCredentialsSettings`

Tunables for the service-to-service OAuth flow.

| Key | Description |
|---|---|
| `TokenLifetimeInHours` | Lifetime of `/oauth/token`-issued service JWTs. Default 12. Longer than user tokens because services have no refresh-token machinery — they re-request. |
| `RequireHttps` | Whether the `/oauth/token` endpoint refuses requests over HTTP. Default `true`. Integration tests flip this off via the AppHost's `--integration-test` flag. |

## `AdminAccountSeedSettings`

Seeds a single admin user on first startup. All fields except `LastName` / `PhoneNumber` / `PhoneNumberConfirmed` are required.

| Key | Description |
|---|---|
| `Email`, `FirstName`, `LastName`, ... | Identity fields for the seeded admin. |
| `Password` | **REQUIRED outside Development.** Outside Dev the service refuses to start without it AND rejects the dev default verbatim (a copy-pasted dev config can't reach prod). |

## `EmailServerSettings`

SMTP credentials for outbound email (registration confirmation, MFA, recovery, lockout notices). Email send happens off the request thread via an in-memory queue + background dispatcher — see [concepts/security-model.md#email-dispatch](../concepts/security-model.md#email-dispatch).

| Key | Description |
|---|---|
| `Host`, `Port` | SMTP relay. |
| `EnableSsl` | TLS toggle. Default `true`. |
| `Username`, `Password` | SMTP auth. Source the password from a secret store in production. |
| `FromAddress`, `FromName` | Envelope sender. |

## `DataRetentionSettings`

Controls the `DataRetentionService` background sweep that prunes expired audit + token rows.

| Key | Description |
|---|---|
| `CleanupIntervalInHours` | How often the sweep runs. Default 12. |
| `RevokedReplayTTLInDays` | How long `RevokedTokenAccessAttempt` audit rows are retained after creation. Default 90. `RevokedTokens` and `RefreshTokens` are pruned by their own natural `ExpiresAt`, no separate TTL. |

## `PublicUrlSettings`

Where this service is publicly reachable. Used by background workers (e.g. the threshold-escalation lock email) to build links — they have no `HttpContext` to derive the URL from.

| Key | Description |
|---|---|
| `BaseUrl` | Scheme + host (+ optional port) of the auth service from a user's browser. No trailing slash. Required outside Development; the dev-only default in `appsettings.Development.json` is `https://localhost:53217`. |

## `HostingSettings`

Per-deployment flags that let the same Docker image run as either an API replica or a worker replica. See [operations/deployment.md §7a](../operations/deployment.md#7a-split-api--worker-deployments-multi-replica) for the multi-replica K8s pattern.

| Key | Description |
|---|---|
| `BackgroundWorkersEnabled` | Default `true`. Set to `false` on API replicas of a split deployment so only the dedicated worker pod runs the cleanup sweep + threshold-escalation worker. |
| `MaxRequestBodySizeInKilobytes` | Default `1024` (1 MB). Cap on inbound request body size, in KB — Kestrel's own default of 30 MB is far larger than any auth endpoint legitimately needs, so we cap tight to shrink the DoS surface. Range: `1` to `30720` (30 MB — past that the config cap stops helping since Kestrel's own default kicks in). Raise if a future endpoint accepts larger payloads (e.g. avatar upload). |

## `IdentitySettings`

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

## `ThresholdEscalationSettings`

Tuning knobs for the `RevokedTokenReplayEscalationService` background worker. See [concepts/security-model.md#threshold-escalation](../concepts/security-model.md#threshold-escalation-on-revoked-token-replay) for the full picture.

| Key | Default | Notes |
|---|---|---|
| `Enabled` | `true` | Master kill switch. Set to `false` during automated load tests where you'd burn through these thresholds artificially. |
| `SweepIntervalInMinutes` | 1 | How often the worker scans the audit table. |
| `WindowInMinutes` | 5 | Sliding-window size used by both thresholds. |
| `WarnThreshold` | 2 | Replays within window that emit the warn-level SIEM event. |
| `LockThreshold` | 5 | Replays within window that lock the account. |

Defaults are aggressive on purpose. Loosen them in deployments where retry-on-old-token churn is expected (e.g. integration tests against a single shared user).

## `DataProtectionSettings`

ASP.NET Core's data-protection key ring is persisted to Redis (required) and optionally protected by a certificate. Identity tokens (password reset, email confirmation, MFA, lockout) are signed with this ring — without persistence, every replica restart invalidates outstanding email-link tokens.

| Key | Description |
|---|---|
| `RedisKey` | Hash key under which the data-protection keys are stored. Default `"AuthService:DataProtectionKeys"`. Must be unique per app sharing a Redis instance. |
| `ApplicationName` | Data-protection isolation name. Replicas of this service must share it; different apps must not. **Do not change once deployed** — invalidates all outstanding Identity tokens. |
| `Certificate.PfxPath` | (Optional) Path to a PFX file containing the cert + private key used to encrypt the key ring at rest. When absent, keys sit in Redis as readable XML — acceptable on a controlled network during initial rollout, but should be populated before the service is exposed broadly. |
| `Certificate.PfxPassword` | (Optional) Password for the PFX. |

## `CorsSettings`

Browser-based clients running on a different origin from the auth service need explicit allow-listing.

| Key | Description |
|---|---|
| `AllowedOrigins` | List of origins (scheme + host + port, no trailing slash) permitted to call the API. Empty list blocks all cross-origin traffic. Wildcards are not supported — explicit allow-list only. |

The default policy pins HTTP methods to `GET / POST / OPTIONS` and headers to `Authorization / Content-Type / Accept`. `AllowCredentials` is intentionally off because JWT bearer tokens travel in the `Authorization` header, not in cookies — flipping it on would forbid wildcards we already don't allow and add a security trap.

`appsettings.Development.json` ships with permissive defaults for common local-dev frontend ports (`http(s)://localhost:3000`, `:4200`, `:5173`) covering React, Angular, and Vite. Production `appsettings.json` ships empty — operators must explicitly override `CorsSettings:AllowedOrigins` for the platform's front-end origins.

## `ForwardedHeadersSettings`

Trust list for the `UseForwardedHeaders` middleware. Behind a load balancer / reverse proxy these MUST be populated, otherwise audit IPs and the rate-limiter's IP partition will all be the proxy's IP rather than the real client. Local-dev with no proxy can leave both empty.

| Key | Description |
|---|---|
| `KnownNetworks` | List of CIDR blocks for trusted upstream proxies (e.g. `["10.0.0.0/8"]`). Most production setups want this. |
| `KnownProxies` | List of specific proxy IPs (e.g. `["203.0.113.10"]`). Use when the LB IPs are stable and explicitly known. |

Only `X-Forwarded-For` and `X-Forwarded-Proto` are honoured. `X-Forwarded-Host` is intentionally not honoured (host-header attack surface).

## `DatabaseSettings`

| Key | Allowed values | Description |
|---|---|---|
| `Provider` | `"MySQL"`, `"SqlServer"`, `"PostgreSQL"` | Picks the EF Core provider `HostExtensions.AddDatabase` dispatches to. Validator rejects any other value at startup. |

Each provider has its own migrations assembly (EF Core requires one model snapshot
per provider per context). See [development/migrations.md](../development/migrations.md)
for the workflow.

## `ConnectionStrings`

The connection string is looked up by name matching the active `DatabaseSettings:Provider`.
Configure **only the one matching your active provider** — leaving the others present
but unused is harmless but adds noise.

| Key | Description |
|---|---|
| `MySQL` | EF Core connection string for MySQL / MariaDB. Used when `DatabaseSettings:Provider = "MySQL"`. |
| `SqlServer` | EF Core connection string for SQL Server. Used when `DatabaseSettings:Provider = "SqlServer"`. Example: `Server=localhost,1433;Database=AuthenticationService;User Id=sa;Password=YourStrong!Passw0rd;TrustServerCertificate=true`. |
| `PostgreSQL` | Npgsql connection string for PostgreSQL. Used when `DatabaseSettings:Provider = "PostgreSQL"`. Example: `Host=localhost;Port=5432;Database=AuthenticationService;Username=postgres;Password=YourStrong!Passw0rd`. |
| `Redis` | StackExchange.Redis connection string for the data-protection key ring. Required in every environment — startup throws on empty. Defaults to `localhost:6379` for local dev. |

## Top-level flags

| Key | Default | Notes |
|---|---|---|
| `RunMigrationsAtStartup` | `true` in Development, `false` (recommended) in production | See [operations/deployment.md §7](../operations/deployment.md#7-database-migrations). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (env-only, no default) | When set, the service exports traces/metrics/logs to this OTLP endpoint. See [operations/observability.md#production-wiring](../operations/observability.md#production-wiring). |
