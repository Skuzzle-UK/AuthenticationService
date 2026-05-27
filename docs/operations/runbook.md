# Operations runbook

> **Status: working runbook.** The core decision tree and common procedures are filled
> in from code knowledge. A few placeholders at the bottom still need team-specific
> input (deployment platform choice, SLO targets, incident-response tooling). Add to
> any section as incidents surface and procedures get exercised.

## Health endpoints

| Endpoint | Purpose |
|---|---|
| `GET /livez` | Liveness probe. Returns 200 if the process is alive. K8s uses this to decide whether to restart the pod. |
| `GET /readyz` | Readiness probe. Returns 200 if MySQL + Redis are reachable. K8s uses this to decide whether to route traffic to this pod. |
| `GET /healthz` | Combined live + ready + dependency check, with detail. For human consumption / dashboards — not probed by K8s. |

Health checks include:
- `mysql_check` — actually opens a connection to MySQL.
- `redis_check` — pings Redis with a 1s timeout (so a hung Redis doesn't take down `/readyz`).
- `AuthenticationService_check` — composite of the above plus startup-state.

## "The service is misbehaving" decision tree

```
Symptoms → Likely cause → Where to look
────────────────────────────────────────

Every authenticated request returns 401
  ├─ Single user? → User's account locked or security stamp rotated → DB: SELECT LockoutEnd, SecurityStamp FROM AspNetUsers WHERE Id = ...
  ├─ All users? → Signing key mismatch → Check JWKS endpoint vs token kid; key-rotation cutover may have happened
  └─ One consumer's users? → Consumer's JWKS cache is stale → Bounce the consumer pod or wait out its RefreshInterval

Login endpoint returns 429
  └─ Rate-limit triggered → Expected during brute-force attempts; check `auth.logins.total{result="failed"}` in Prometheus
                          → If legitimate traffic, see ../concepts/security-model.md#rate-limiting — tighten / loosen the policy

Refresh endpoint returns 401 unexpectedly
  ├─ Reuse cascade fired → DB: SELECT * FROM RefreshTokens WHERE UserId = ... ORDER BY CreatedAt DESC
  │                       → Look for ConsumedAt timestamps; the "second consume" attempt is the trigger
  └─ Token genuinely expired (5d) → User must log in fresh

/oauth/token returns 500
  ├─ Grab the response body — B2's ProblemDetails handler stamps a `traceId`.
  │  Grep Serilog logs / Loki for that traceId to find the structured exception.
  ├─ DB unreachable mid-request? → mysql_check on /readyz should already be red.
  │  Look for "MySqlRetryingExecutionStrategy" retry-exhaustion in the log.
  ├─ Signing-key load failure on startup? → would have crashed startup, not surfaced here.
  │  But check startup logs (`Loaded ES256 signing key`) appear at least once.
  └─ Genuine controller bug? → the controllers log structured events at every branch
     (`SecurityEventIds.ClientCredentialsToken*`); look at the 6xxx EventIds around the
     failure timestamp to see how far the request got before the exception.

Email isn't arriving
  ├─ SMTP credentials wrong → Check EmailServerSettings__Password env var
  ├─ Queue full → Look for LogError "Email queue full" entries (security-model.md#email-dispatch)
  └─ Specific recipient → Check SMTP relay's bounce log

/readyz reports unhealthy
  ├─ mysql_check fails → MySQL unreachable; check ConnectionStrings__MySQL and network
  ├─ redis_check fails → Redis unreachable; in-memory rate-limit fallback active; named policies (auth-strict etc.) are gone until Redis recovers
  └─ Check Aspire dashboard / Grafana for which dependency is red
```

## Common procedures

### Force a user's password reset
- Admin endpoint: `POST /api/Admin/users/{id}/force-password-reset`
- Effect: user gets a reset email immediately, all refresh tokens revoked, current access token added to deny-list.
- Covered by integration scenario 9.

### Lock an account
- Admin endpoint: `POST /api/Admin/users/{id}/lock`
- Effect: account locked indefinitely; existing sessions are NOT auto-revoked, so pair with `POST /api/Admin/users/{id}/revoke-sessions` if the user is suspected compromised.
- Recovery path: forgot-password flow clears the lockout on successful reset.
- User-driven alternative: the "wasn't me!" link in password-changed emails (`POST /api/Account/lock`) locks the user's own account.

### Issue an emergency `/logoutall` against a user
- Admin endpoint: `POST /api/Admin/users/{id}/revoke-sessions`
- Effect: every refresh-token family for the user is revoked + security stamp rotated. Every outstanding access token dies on next validation.

### Provision a new service-to-service client
- Admin endpoint: `POST /api/Admin/clients`
- Response carries the **one-time-display** client_secret. Capture it for the consuming service's secret store.
- See [concepts/service-to-service.md](../concepts/service-to-service.md).

### Rotate a compromised client secret
- Admin endpoint: `POST /api/Admin/clients/{id}/rotate-secret`
- Response carries the new one-time-display secret. The old one stops working immediately.

### Rotate the signing key
- See [key-rotation.md](key-rotation.md).

### Disaster recovery (signing key lost)
- See [signing-key-backup-and-restore.md](signing-key-backup-and-restore.md) — universal
  backup/restore runbook covering Azure Key Vault, AWS Secrets Manager, HashiCorp Vault,
  GCP Secret Manager, Kubernetes Secrets + Velero, Sealed Secrets / SOPS, and filesystem
  snapshots. Includes the "all keys lost" procedure with consumer-communication ordering.

### Triage "I can't log in" reports

When a user says they can't sign in, the failure shape they're seeing narrows the cause.
Ask for the exact response or error before opening a DB session — that alone usually
identifies the branch below.

| What the user / their client reports | Probable cause | Quick check |
|---|---|---|
| HTTP 401 with `"AccountLocked"` | `LockoutEnd` is set in the future, OR `AccessFailedCount` tripped the threshold | `SELECT LockoutEnd, AccessFailedCount FROM AspNetUsers WHERE NormalizedEmail = upper(:email)` |
| HTTP 401 with `"EmailNotConfirmed"` | They never clicked the confirmation link in their registration email | `SELECT EmailConfirmed FROM AspNetUsers WHERE NormalizedEmail = ...` — if `0`, resend via `POST /api/Registration/confirm/email` |
| HTTP 401 with `"InvalidCredentials"` (generic) | Wrong password — generic on purpose to avoid leaking which field was wrong | Check `auth.logins.total{result="failed"}` for that user's IP in Prometheus. If a brute-force pattern, look for `EventId 1006` (`FailedLoginLockoutTriggered`). |
| HTTP 401 with `"MfaRequired"` and an `MfaChallenge` payload | User authenticated correctly but hasn't completed MFA. Not a failure — the response shape says "now POST the code." | Confirm the user knows their MFA path (authenticator app / email / phone). If they've lost the device, see [Admin recovery — reset-mfa](admin-recovery.md) or admin endpoint `POST /api/Admin/users/{id}/reset-mfa`. |
| HTTP 200 but `/api/Account/me` says different roles than expected | Their session pre-dates a role change. | They need to log out + log back in. Server-side, an admin can force this via `POST /api/Admin/users/{id}/revoke-sessions`. |
| HTTP 401 right after a successful login | The threshold-escalation worker (`EventId 4005`) auto-locked the account mid-session after sustained revoked-token replay. | `SELECT * FROM RevokedTokens WHERE UserId = ... AND LockedAt IS NOT NULL ORDER BY LockedAt DESC LIMIT 5`. Account needs admin unlock + forgot-password flow. |

Last-resort recovery if the user is the **seeded admin** and none of the above applies:
[admin-recovery.md](admin-recovery.md) covers three break-glass paths (raw SQL, CLI subcommand, env-var override).

## Recurring tasks

- **Signing-key rotation.** Pick a cadence (suggested: quarterly). [key-rotation.md](key-rotation.md).
- **Data-protection cert rotation.** Less common. See [deployment.md §4](deployment.md#4-configure-data-protection-at-rest-encryption-recommended).
- **Review of SIEM rules.** Quarterly. Are the `EventId = 1008` / `4005` pages still happening? Is the threshold tuning still correct?
- **Audit retention check.** Confirm `DataRetentionSettings` is pruning at the right rate; check DB row counts on `RevokedTokenAccessAttempts` and `SecurityEvents` against expected volume.

## Items still needing team-specific input

These placeholders need decisions or platform context the codebase can't supply. As
the relevant decision lands, replace the bullet with the concrete playbook.

- **First-time deployment to production.** Need to capture concrete steps for the
  chosen platform: Helm chart values, Terraform module signature, Pulumi stack, or the
  raw `kubectl apply` flow. The shape this section should take, once written:
  1. Image registry + tag-pinning strategy
  2. Secret provisioning (which fields land in which store — cross-link to
     [signing-key-backup-and-restore.md](signing-key-backup-and-restore.md) for the
     JWT key story)
  3. First-boot ordering vs. MySQL / Redis dependencies
  4. Smoke test after first traffic (login + /readyz + JWKS round-trip)
  5. Rollback procedure if the smoke test fails

- **SLO / SLA targets.** What availability does the platform commit to? Suggested
  shape when decided:
  - Availability target (e.g. 99.9% rolling 30-day).
  - Latency target on the hot endpoints (login, refresh, /oauth/token, JWKS) at p95
    and p99.
  - Error-budget policy: what happens if the budget is exhausted (freeze deploys?
    reduce rollout speed?).
  - Reference Grafana dashboard panel(s) that prove the SLO is being met.

- **Incident response procedure.** Once on-call rotation + paging tool are picked:
  - Severity matrix (what counts as a P1 vs P2 — `EventId 1008` refresh-reuse is
    almost certainly P1; `EventId 4004` threshold-warned is probably P3).
  - Paging chain (who's first responder, who's escalation, what hours).
  - Comms-during-incident expectations (status page? Slack channel? Both?).
  - Post-incident review cadence and template.

## Reference

- [Architecture overview](../architecture.md)
- [Security model](../concepts/security-model.md)
- [Configuration reference](../reference/configuration.md)
- [SIEM contract](observability.md#siem-contract)
