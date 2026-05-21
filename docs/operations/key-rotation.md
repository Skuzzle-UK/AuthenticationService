# Signing-key rotation

Zero-downtime runbook for rotating the ES256 signing key.

## How key loading works

`EcdsaKeyProvider` loads **every `*.pem` in `JWTSettings.PrivateKeyDirectory`** and publishes them all in JWKS, so multiple keys can co-exist during a rotation overlap. `JWTSettings:ActiveKeyId` (the JWK thumbprint) picks which one signs new tokens.

The implication: rotation is a directory-content operation plus a one-line config flip, not a redeploy.

## The runbook

### 1. Stage the new key

Generate a fresh ES256 PEM (see [deployment.md §1](deployment.md#1-generate-the-signing-key)) and drop it into `PrivateKeyDirectory` alongside the existing one. Restart / rolling-restart the auth service.

After this step:

- Both keys are loaded.
- The JWKS endpoint returns both.
- **The old key is still active** — `ActiveKeyId` hasn't changed, so new tokens are still signed with it.
- The new key sits idle, advertised but unused.

### 2. Wait for consumer JWKS caches to refresh

JwtBearer's default JWKS cache TTL is **24 hours**. Either wait that out, or — if your rotation needs to be faster — tighten `BackchannelTimeout` / `RefreshInterval` on consumers, or trigger a manual re-fetch by recycling them.

Until every consumer has the new key in their cache, the cutover in step 3 will reject tokens at validation.

### 3. Cut over

Set `JWTSettings:ActiveKeyId` to the new key's `kid` and restart.

- New tokens are now signed with the new key.
- Existing in-flight tokens (signed by the old key) still validate because the old key is still loaded and still in JWKS.

The `kid` you publish to ops for this step is the value visible in the JWKS endpoint's `kid` field (also logged at startup: `Loaded ES256 signing key {KeyId} from '{Path}'`).

### 4. Drain

Wait at least `JWTSettings:ExpiryInMinutes` (default 5) plus `RefreshTokenExpiryInDays` if you also want refresh tokens issued under the old key to drain, then a small safety margin. After that, no token signed by the old key is still valid.

### 5. Decommission the old key

Remove the old PEM from `PrivateKeyDirectory` and restart. The JWKS endpoint stops advertising it. Move the file to long-term cold storage (or destroy, per your key-management policy) — it should never be possible to re-introduce a retired key by accident.

## Consumer-side notes

Consumers using `Authority`-based JwtBearer auto-refresh JWKS every 24 hours by default, so they pick up new keys without redeployment. Tighten that interval if your rotation cadence is faster than 24 hours.

## Routine rotation cadence

Decide a cadence (e.g., quarterly) and put it on the calendar. The runbook above is the same every time — the only operational question is "are consumers still pointing at the canonical hostname?" Yes? Then run the runbook.

## Emergency rotation (suspected key compromise)

Same runbook, faster. The window in step 2 (consumer JWKS cache refresh) becomes the bound on how quickly the old key can be retired:

1. Stage the new key (step 1).
2. **Immediately tighten consumer `RefreshInterval`** so caches re-fetch in minutes rather than 24 hours, OR roll consumer pods to force a cold start.
3. Cut over (step 3) once caches have refreshed.
4. **Skip the drain** if the suspected compromise window means in-flight old-key tokens are themselves suspect — decommission the old key immediately (step 5). Acceptable side-effect: any legitimate user holding an in-flight old-key token gets a 401 and needs to refresh, which is the cost of an emergency rotation.

## Disaster recovery (all keys lost)

If `PrivateKeyDirectory` is empty in non-Development environments, the service refuses to start. If you've also lost your backups (a *very* bad day):

1. Provision a fresh key (deployment.md §1).
2. Inject it into `PrivateKeyDirectory`.
3. Start the service. JWKS now publishes only the new key.
4. **Every existing token is invalid.** Every user must log in again. Every refresh token is dead. Every issued service token is dead.
5. Communicate to platform consumers — they'll see 401s until their JWKS caches refresh and they pick up the new key.

This is why the **signing-key backup story** is on [`TODO.md`](../../TODO.md) as a deployment requirement. Whatever your secret-store of choice is (Key Vault / Secrets Manager / Vault), confirm:
- The key material is backed up.
- Restore from backup is exercised at least once.
- The runbook for "all keys lost" is written down somewhere a person on-call can find it.
