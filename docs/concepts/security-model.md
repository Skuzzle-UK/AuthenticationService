# Security model

The defence-in-depth picture: what protections sit at which layer, what we explicitly chose not to do, and where you'll find each one in the code.

## Crypto

- **Signing algorithm: ES256 (ECDSA P-256 + SHA-256).** Restricted by `TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256]` both server-side (in token validation) and consumer-side (in TokenValidationLib). This prevents algorithm-confusion attacks where a forger uses HS256 with the public key as the shared secret.
- **Key storage: PEM files in `JWTSettings.PrivateKeyDirectory`.** Auto-generated in Development, operator-supplied via secret mount in production. See [operations/key-rotation.md](../operations/key-rotation.md).
- **Public keys via JWKS.** No shared secrets between auth service and consumers — they fetch the public key via the standard `/.well-known/jwks.json` endpoint.
- **Data-protection key ring persisted to Redis,** optionally protected at-rest by a PFX cert. Without this, every replica restart invalidates outstanding email-link tokens. See [operations/deployment.md §3-4](../operations/deployment.md#3-provision-redis).

## Revoked-token deny-list

Access tokens have a 5-minute TTL by design. Within that window, **revocation isn't waited out** — the auth service maintains a `RevokedTokens` deny-list and `RevokedTokenMiddleware` checks every incoming request before it reaches a controller:

| Trigger | What's revoked |
|---|---|
| `POST /api/Authentication/logout` | Current access token. |
| `POST /api/Authentication/logoutall` | Every access token via security-stamp rotation; refresh families all revoked. |
| Refresh-token reuse cascade ([refresh-rotation.md](refresh-rotation.md)) | Every access token (security stamp rotated) + every refresh family. |
| Password change | Every access token (security stamp rotated). |
| Threshold-escalation lock | Every access token + every refresh family. |

Replays of revoked tokens are recorded in `RevokedTokenAccessAttempts` (forensic + escalation input). The middleware doesn't blindly JWT-parse non-Bearer headers — `Basic` credentials on `/oauth/token` pass through cleanly. See `RevokedTokenMiddleware.cs`.

**Note:** other microservices accept tokens until natural `exp` — they don't share the deny-list. The 5-minute access-token TTL is the bound on cross-service revocation latency. If instant cross-service revocation is needed, add a token-introspection endpoint or pub/sub. Tracked as future work.

## Threshold escalation on revoked-token replay

The `RevokedTokenReplayEscalationService` background worker watches `RevokedTokenAccessAttempts` for sustained replay of already-revoked tokens. Two thresholds, both within a sliding window:

| Threshold | Default | What happens |
|---|---|---|
| **Warn** | 2 replays in 5 min | Emits `RevokedTokenReplayThresholdWarned` (4004, Warning). No user-facing impact. Useful for spotting buggy clients in retry loops. |
| **Lock** | 5 replays in 5 min | Locks the account indefinitely (`LockoutEnd = MaxValue`), revokes every refresh-token family for the user, rotates the security stamp, emails the user a recovery link. Emits `RevokedTokenReplayThresholdLocked` (4005, Critical). |

**Idempotency.** Each escalation level stamps a column on the `RevokedToken` row (`WarnedAt`, `LockedAt`) so it fires once per incident, not once per sweep.

**Recovery** follows the standard reset-password flow — see [concepts/user-auth-flows.md#lockout--recovery](user-auth-flows.md#lockout--recovery). The lock-notification email includes a ready-made reset link, so the user doesn't need their app's UI to surface a "forgot password" affordance.

Tuning lives in [reference/configuration.md](../reference/configuration.md#thresholdescalationsettings).

## Rate limiting

Cluster-wide via Redis. Three layered policies plus a health-check carve-out:

| Policy | Limit (Redis, cluster-wide) | Applied to |
|---|---|---|
| Global default | 4 req / 10s per user (or per IP if anonymous) | Every endpoint as a catch-all |
| `auth-strict` | 10 req / minute per IP | Unauthenticated credential / link endpoints (login, MFA, register, forgot-password, **`/oauth/token`**) |
| `auth-sensitive` | 10 req / minute per user | Authenticated state-changing endpoints (change-password, enable-MFA) |
| Health-check carve-out | 30 req / 10s per IP | `/livez`, `/readyz`, `/healthz` — orchestrator probes shouldn't be throttled |

Most-restrictive across all applicable limiters wins per request.

**In-memory fallback when Redis is down.** The global limiter is *chained* — Redis primary plus an in-memory limiter as fallback. When Redis is up, Redis caps are the binding constraint. When Redis goes down, the in-memory fallback takes over while the readiness probe pulls the replica out of service (~10-30s). Self-heals when Redis recovers.

The named policies (`auth-strict`, `auth-sensitive`) are Redis-only and fail-open if Redis is down — they vanish until Redis recovers. The global in-memory fallback covers them in degraded mode.

## Password policy

Defaults match NIST 800-63B / OWASP guidance:

- 12 character minimum (configurable to 14/16 for higher-assurance environments)
- Digit + lowercase + uppercase + non-alphanumeric required
- Lockout after 3 failed attempts (auto-clears in 2 minutes)
- Reserved-username deny-list at registration

Full tunables in [reference/configuration.md#identitysettings](../reference/configuration.md#identitysettings).

## Reserved usernames

`IdentitySettings.User.ReservedUserNames` blocks claims on names that should remain reserved for platform identities (`administrator`, `root`, `noreply`, `support`, etc.) at registration time. Setting this in config **replaces** the default list — copy the defaults out and extend rather than start from scratch.

## Email dispatch

Outbound email goes through an **in-memory queue + background dispatcher** rather than blocking the request thread on SMTP. Controllers call `_emailService.SendEmailAsync(...)` which writes to a bounded `Channel<T>` and returns immediately; a `BackgroundService` reads from the channel and does the actual SMTP work off the request path.

The dispatcher uses MailKit and **holds the SMTP connection open across messages**. Connection reuse + SMTP pipelining means a sustained burst amortises the TLS-handshake / auth cost — typically 3-10× the throughput of fresh-connect-per-send.

**What this changes:**
- Login / registration / forgot-password requests no longer wait for SMTP. A slow or hung SMTP server doesn't stall the auth service's request handling.
- SMTP errors after queueing are logged but **not** propagated back to the controller — by design, a downstream email problem shouldn't fail the user's request mid-flow.

**Failure modes:**

| Symptom | What happens | Operator action |
|---|---|---|
| SMTP slow | Queue absorbs the latency; controllers stay fast. Dispatcher catches up when SMTP recovers. | None — system self-heals. |
| SMTP throws on send | Logged at `Error`. Message is dropped. Dispatcher continues with the next message. | Investigate the SMTP server; the user can re-trigger the email by re-running the flow. |
| Sustained SMTP outage filling the queue | After ~1000 messages the queue is full. Producers wait up to 1 second for space, then log + drop. | Investigate SMTP. The `LogError` "Email queue full" entries are the alert signal. |
| Replica restart with messages still in the queue | Anything not yet drained is lost. | None — auth-service email volumes are low enough that this loss window is tiny. For compliance-driven persistence, swap the queue for Hangfire / similar. |

**Per-replica queue.** Each replica has its own in-memory channel and dispatcher. Whichever replica receives the request also dispatches its own emails — the dispatcher runs on every replica that queues, regardless of `HostingSettings:BackgroundWorkersEnabled`.

## Security response headers

Every response carries a small set of security headers as defence-in-depth backstops. Implemented in `SecurityHeadersMiddleware`, applied early in the pipeline (right after `UseStaticFiles()`) so every response — including 404s, static files, and Razor pages — gets them.

| Header | Value | Why |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'`, `script-src 'self' 'unsafe-inline'`, `frame-ancestors 'none'`, etc. | Locks down what scripts / styles / images / iframes the browser will load. Defends against XSS even if a payload reaches our HTML. Razor pages need `'unsafe-inline'` for now; tighten to nonce-based later if needed. |
| `X-Content-Type-Options` | `nosniff` | Stops the browser overriding our Content-Type. Defends against MIME-confusion attacks. |
| `X-Frame-Options` | `DENY` | Refuses iframe embedding. Defends against clickjacking. Duplicated by CSP `frame-ancestors 'none'` for older browsers. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Caps what gets sent in `Referer` on outbound requests. Stops us leaking URLs (which contain reset-password tokens!) to third-party sites. |
| `Permissions-Policy` | empty allow-lists for `camera`, `microphone`, `geolocation`, `payment`, `usb`, `fullscreen` | Disables browser features the auth service has no business using. Defence in depth. |

`HSTS` is set separately in `WebApplicationExtensions.ConfigureApplicationAsync` (only in non-Development).

## CORS

Browser-based clients on a different origin from the auth service need explicit allow-listing via `CorsSettings:AllowedOrigins`. Empty list blocks all cross-origin traffic. No wildcards — explicit allow-list only. `AllowCredentials` is intentionally off because JWT bearer tokens travel in the `Authorization` header, not in cookies.

`appsettings.Development.json` ships with permissive defaults for common local-dev frontend ports (`http(s)://localhost:3000`, `:4200`, `:5173`). Production `appsettings.json` ships empty.

## Audit pipeline → SIEM

Every security-relevant event is logged via Serilog with a stable `EventId.Id` from `SecurityEventIds`. The numeric ranges are:

| Range | Category | Examples |
|---|---|---|
| 1000s | Authentication | LoginSucceeded, LoginFailed, MFA events, refresh rotation/reuse, logout |
| 2000s | Registration | Registration, email confirmation |
| 3000s | Account management | Password changes/resets, lockout, MFA enable |
| 4000s | Token state | Token revocation, replay attempts, threshold-escalation fires |
| 5000s | Admin / s2s | Admin actions, client credentials issued/denied/created |

SIEM rules match on these IDs rather than message strings, so values are stable across deploys. See [operations/observability.md#siem-contract](../operations/observability.md#siem-contract) for the wiring and recommended detections.
