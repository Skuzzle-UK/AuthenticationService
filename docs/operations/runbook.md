# Operations runbook

> **Status: skeleton.** This doc is the canvas for ops procedures discovered as the service is actually operated. Add to it as incidents surface and procedures get exercised. Items marked **TBD** below need writing once an ops person has done them at least once — premature writing means the doc drifts before it's ever read.

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
  └─ Look at SIEM EventId 5xxx events around the failure time
  └─ Common cause TBD — needs ops experience to enumerate

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
- See [key-rotation.md#disaster-recovery-all-keys-lost](key-rotation.md#disaster-recovery-all-keys-lost).

## Recurring tasks

- **Signing-key rotation.** Pick a cadence (suggested: quarterly). [key-rotation.md](key-rotation.md).
- **Data-protection cert rotation.** Less common. See [deployment.md §4](deployment.md#4-configure-data-protection-at-rest-encryption-recommended).
- **Review of SIEM rules.** Quarterly. Are the `EventId = 1008` / `4005` pages still happening? Is the threshold tuning still correct?
- **Audit retention check.** Confirm `DataRetentionSettings` is pruning at the right rate; check DB row counts on `RevokedTokenAccessAttempts` and `SecurityEvents` against expected volume.

## Items to be filled in over time

The following placeholders need first-hand operational experience to write usefully. As they're exercised, replace the **TBD** with the actual playbook.

- **TBD: First-time deployment to production** — concrete steps for a real platform (Helm chart? Terraform? Pulumi? Plain kubectl?), not generic K8s YAML.
- **TBD: Backup + restore for the signing-key directory** — depends on the chosen secret store. See [TODO.md](../../TODO.md) "No backup / disaster-recovery story for signing keys."
- **TBD: SLO / SLA targets** — what's the platform's stance on auth-service availability? 99.9%? 99.95%? Decide and write it here.
- **TBD: Incident response procedure** — on-call rotation, paging tool, escalation matrix.
- **TBD: How to triage a user-reported "I can't log in"** — concrete steps. The decision tree above is a start.

## Reference

- [Architecture overview](../architecture.md)
- [Security model](../concepts/security-model.md)
- [Configuration reference](../reference/configuration.md)
- [SIEM contract](observability.md#siem-contract)
