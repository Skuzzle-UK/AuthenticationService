# Observability

The auth service emits **traces, metrics, and logs** via OpenTelemetry. Production exports to whatever OTLP collector the platform provides. Locally, the Aspire AppHost spins up a Grafana / Tempo / Loki / Prometheus stack so you can see everything in context while developing.

## Local stack via Aspire

Hitting F5 on `AuthenticationService.AppHost` brings up an extra container alongside the existing MySQL / Redis / smtp4dev:

| Container | Image | Endpoints |
|---|---|---|
| `grafana` | `grafana/otel-lgtm` | Grafana UI on `:3000`, OTLP gRPC on `:4317`, OTLP HTTP on `:4318` |

The LGTM image bundles all four signals — Loki (logs), Grafana (UI), Tempo (traces), Mimir/Prometheus (metrics) — in one container with datasources pre-wired. The auth service exports OTLP to the container's gRPC endpoint, gated on `OTEL_EXPORTER_OTLP_ENDPOINT` being set (Aspire wires this automatically).

**Skip in test mode:** integration tests pass `--integration-test`, which omits the container — telemetry isn't part of what they assert and the extra container slows boot.

**Open the UI:** `http://localhost:3000`. The Prometheus / Tempo / Loki datasources are pre-wired — metrics, traces, and logs are immediately visible via the Explore tab without any config on our end.

**Starter dashboard** at [`AuthenticationService.AppHost/grafana/dashboards/auth-overview.json`](../../AuthenticationService.AppHost/grafana/dashboards/auth-overview.json) — twelve panels covering login rate, MFA adoption, refresh-token reuse fires, threshold-escalation locks, request latency p95, EF Core query durations, and more. **Auto-imported** by the AppHost via Grafana's HTTP API once the container reports ready — see `GrafanaDashboardProvisioner.cs`. The import is idempotent (`overwrite: true`), so iterating on the dashboard JSON and re-running the AppHost applies the updates. (File-based provisioning via bind-mount would be the cleaner route but Docker Desktop on Windows rejects single-file mounts; the HTTP-API import sidesteps that.)

## What's instrumented

| Signal | Source | Where |
|---|---|---|
| Traces — HTTP requests | `OpenTelemetry.Instrumentation.AspNetCore` | All controllers, filters out `/livez` `/readyz` `/healthz` to keep probe noise out of Tempo |
| Traces — outbound HTTP | `OpenTelemetry.Instrumentation.Http` | Email / SMS / any HttpClient |
| Traces — EF Core queries | `OpenTelemetry.Instrumentation.EntityFrameworkCore` | Every DB query nested under the request that issued it |
| Metrics — framework | ASP.NET Core / HttpClient / Runtime instrumentation | Per-endpoint latency, GC, etc. |
| Metrics — custom | `AuthenticationService.Observability.AuthMetrics` | Login rate, MFA, refresh, lockouts, reuse, etc. — see table below |
| Logs | Serilog → OTLP sink | Routed to Loki, correlated with trace IDs |

All instrumentation lives in `AuthenticationService.ServiceDefaults/Extensions.cs`'s `ConfigureOpenTelemetry`. Custom metrics in `AuthenticationService/Observability/AuthMetrics.cs`.

## Custom business metrics

Counters fire alongside the existing `_logger.Log(SecurityEventIds.X, ...)` calls. Every emit-site is in the controllers / `JWTService` / `RevokedTokenReplayEscalationService`.

| Metric | Tags | What |
|---|---|---|
| `auth.logins.total` | `result`, `mfa_used` (success), `reason` (failure) | Login attempts |
| `auth.mfa.challenges.total` | `provider` | MFA challenges issued |
| `auth.mfa.verifications.total` | `result` | MFA code verification outcomes |
| `auth.refreshes.total` | — | Refresh-token rotations |
| `auth.refresh.reuse_detected.total` | — | Reuse cascade fires (every increment is a security incident) |
| `auth.lockouts.total` | `trigger` (`failed_login` / `user` / `threshold_escalation`) | Account lockouts |
| `auth.password_changes.total` | — | Authenticated password changes |
| `auth.password_resets.total` | `stage` (`requested` / `completed`) | Forgot-password milestones |
| `auth.mfa.enabled.total` | `provider` | MFA-enable events (counter, NOT the running total — see gauges) |
| `auth.tokens.revoked.total` | `reason` | Access-token revocations |
| `auth.revoked_token.replay.total` | `severity` | Revoked-token replay attempts |
| `auth.threshold_escalation.fires.total` | `level` (`warned` / `locked`) | Escalation worker fires |

Plus three observable gauges refreshed every 60s by `UserGaugeRefreshService`:

| Gauge | What |
|---|---|
| `auth.users.total` | Total registered users |
| `auth.users.mfa_enabled.total` | Users with MFA currently enabled |
| `auth.users.locked.total` | Users in an active lockout |

The refresh service is gated on `HostingSettings:BackgroundWorkersEnabled` — in a multi-replica deployment, only the worker pod needs to run it (every replica would return the same global count from the same DB).

## Trace ↔ log correlation

Serilog's OTLP sink picks up the active `Activity`'s `trace_id` and `span_id` from context, so log records in Loki carry the same trace IDs as the spans in Tempo. Clicking a span in Grafana surfaces the logs emitted during that request without needing a separate join.

## Production wiring

Set `OTEL_EXPORTER_OTLP_ENDPOINT` on the auth service to your platform's OTLP collector endpoint (e.g. `http://otel-collector.platform:4317`). The same exporter serves traces + metrics + logs; no separate per-signal config needed. Skip the env var entirely (default for plain `dotnet run`) and the service runs console-only — no failed-export retries, no telemetry costs.

## SIEM contract

The service emits structured logs via Serilog. In production, point the platform's log aggregator at the container's stdout — output is JSON-line when the `Compact` formatter is active. Every log line carries:

- `RequestId` / `TraceId` — request correlation. `TraceId` is the join key against trace spans.
- `EventId.Id` and `EventId.Name` — for security-relevant events, taken from `SecurityEventIds`. SIEM rules match on these IDs rather than message strings, so values are stable across deploys.

Security events span four numeric ranges:

| Range | Category | Examples |
|---|---|---|
| 1000s | Authentication | `LoginSucceeded` (1001), `LoginFailed` (1002), `MfaChallengeIssued` (1003), `MfaVerified` (1004), `MfaFailed` (1005), `FailedLoginLockoutTriggered` (1006), `RefreshTokenRotated` (1007), `RefreshTokenReuseDetected` (1008, **Critical**), `LogoutPerDevice` (1009), `LogoutAllDevices` (1010) |
| 2000s | Registration | `RegistrationCompleted` (2001), `EmailConfirmed` (2002), `EmailConfirmationFailed` (2003) |
| 3000s | Account management | `PasswordChanged` (3001), `PasswordResetRequested` (3002), `PasswordResetCompleted` (3003), `AccountLockedByUser` (3004), `MfaEnabled` (3005) |
| 4000s | Token state | `TokenRevoked` (4001), `RevokedTokenReplayAttempt` (4002), `OrphanedTokenRevoked` (4003), `RevokedTokenReplayThresholdWarned` (4004), `RevokedTokenReplayThresholdLocked` (4005, **Critical**) |
| 5000s | Admin / s2s | Admin actions, `ClientCredentialsTokenIssued`, `ClientCredentialsTokenDenied`, `ClientCreated`, `ClientSecretRotated`, `ClientDisabled` |

### Field-shape contract

- `UserId` — always the `sub` claim / `User.Id`. Empty string when the target user doesn't exist (failed login on unknown email).
- `IpAddress` — caller's IP, post-`UseForwardedHeaders` so it's the real client.
- `UserAgent` — auto-attached to every log event during an HTTP request via `HttpContextLogEnricher`. Comes from the request's `User-Agent` header verbatim; absent from worker-emitted events (threshold-escalation worker, data-retention sweep) which have no `HttpContext`.
- `Jti` — access-token jti claim.
- `FamilyId` — refresh-token family / `sid` claim.
- `Reason` — `LoginFailureReason` or `RevocationReasons` value.
- `Provider` — `MfaProviders` enum.
- `Severity` — `Severity` enum (used on revoked-token replay attempts).

PascalCase, same name = same meaning across every event.

### SIEM rules that benefit from `UserAgent`

- `EventId = 1001` (LoginSucceeded) `GROUP BY UserId` — flag when a user's typical UA shifts (e.g. Chrome → curl, or browser → Python script). Behavioural signal of credential theft or account-sharing.
- Same `Jti` seen with multiple distinct UAs in a short window — token-sharing or forwarded-credential signal.
- Login UA vs refresh UA diff for the same `FamilyId` — suggests the refresh token left the original device/browser.

### PII posture

- `UserId` is logged for forensic correlation.
- **Email addresses, passwords, tokens, refresh-token values, and authenticator secrets are never logged.** If an investigator needs to map `UserId` to email, they go to the auth DB (which has its own retention policy).

### Recommended SIEM detections to wire up first

- `EventId = 1008` (RefreshTokenReuseDetected) — page on every occurrence. High-confidence theft signal.
- `EventId = 4005` (RevokedTokenReplayThresholdLocked) — page on every occurrence. The threshold-escalation worker has just locked an account because someone hammered with a stolen access token.
- `EventId = 1002 GROUP BY UserId` with count > N in 60 seconds — credential stuffing against a known user.
- `EventId = 1002 WHERE UserId IS EMPTY GROUP BY IpAddress` — credential scanning against unknown emails from one source.
- `EventId = 1006` (FailedLoginLockoutTriggered) — informational, useful to see in dashboards.
- `EventId = 4002 GROUP BY Jti` with count > 5 — automated replay of a revoked token (the worker handles this for you, but the SIEM rule is a useful belt-and-braces if the worker is disabled).
- `EventId = 4004` (RevokedTokenReplayThresholdWarned) — early-warning bug detection. A misbehaving SPA in a retry loop will fire this against a logged-out user; an attacker will progress past it to 4005 quickly.
