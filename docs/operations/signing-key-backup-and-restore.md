# Signing-key backup and restore

The auth service's ES256 signing keys are the single most valuable secret it holds:
lose them and **every issued token is invalid until a fresh key is provisioned and
consumer JWKS caches refresh** — a full re-auth event for every user. This doc is the
runbook for preventing that scenario, and for surviving it if it happens.

This is intentionally **secret-store-agnostic**. The team can pick whichever option fits
the deployment platform; the universal part of the doc tells you what to back up and
what makes a backup correct, and the per-platform sections give the concrete commands.

> See also: [`key-rotation.md`](key-rotation.md) for the routine + emergency *rotation*
> runbooks. Rotation is what you do when a key is suspected compromised; the doc you're
> reading is what you do when keys are *gone* (deleted, encrypted by ransomware, lost
> in a regional outage, etc.) — different failure mode, different procedure.

---

## What you're backing up

The auth service reads ES256 (NIST P-256) ECDSA private keys from
`JWTSettings:PrivateKeyDirectory` (default `keys/` relative to content root).

| Artifact | Format | Quantity |
|---|---|---|
| Private key file(s) | PEM-encoded EC private key (`-----BEGIN EC PRIVATE KEY-----`) | One or more `.pem` files |
| Filename | Free-form — `EcdsaKeyProvider` reads every `*.pem` in the directory | n/a |
| Active-key marker | `JWTSettings:ActiveKeyId` config value = the active key's JWK thumbprint | One per environment |

**Filenames don't matter.** The Key ID (the `kid` field in JWKS and the JWT header) is
derived from the JWK thumbprint of the public key, not the filename. You can rename PEM
files freely without breaking anything, as long as the bytes inside don't change.

**The active-key marker is part of the backup.** Restoring the PEM files without also
restoring `JWTSettings:ActiveKeyId` means the service will fall back to "first key it
finds in the directory" (with a startup log line). For a single-key setup that's fine;
during a rotation overlap it's wrong.

---

## What makes a backup correct

A backup is correct when **all three** hold:

1. **Completeness** — every `*.pem` in `PrivateKeyDirectory` is captured. A subset means
   issued tokens signed under the missing key fail validation after restore.
2. **Integrity** — the bytes round-trip. Easy proof: SHA-256 each PEM file before backup,
   compare after restore.
3. **Verifiability** — a JWT signed under one of the restored keys validates against the
   JWKS endpoint the auth service serves after restore. This is the only check that
   exercises the full pipeline (file → parser → JWK → signing credentials → JWKS export
   → consumer validation). See [Restore-test cadence](#restore-test-cadence) below.

---

## Deployment patterns (how keys reach the pod)

Before talking about backup mechanisms, a sketch of how the PEMs typically get from a
secret store to `PrivateKeyDirectory` on a running pod. The backup strategy depends
slightly on which pattern you use.

| Pattern | How the pod gets the keys | Backup is of… |
|---|---|---|
| **Mounted secret store (CSI driver)** | Azure Key Vault / AWS Secrets Manager / GCP Secret Manager projects secrets as files via the Secrets Store CSI driver. Pod sees them as files under `/mnt/secrets/keys/`. `PrivateKeyDirectory` is set to that path. | The secret store itself. |
| **Init-container fetch** | An init container runs `vault kv get …` (or `aws secretsmanager get-secret-value`, etc.) and writes PEMs to an `emptyDir`. Main container mounts the same `emptyDir` as `PrivateKeyDirectory`. | The secret store itself. |
| **Sidecar / app-direct fetch** | App fetches at startup. Not currently implemented; would need an `EcdsaKeyProvider` variant. Out of scope. | n/a |
| **Kubernetes Secret + projected volume** | Plain `kind: Secret` mounted at `PrivateKeyDirectory`. | The Secret object (via `etcd` backup or a tool like Velero). |
| **Sealed Secrets / SOPS in git** | Encrypted PEMs committed to the repo, decrypted at deploy time by Sealed Secrets Controller or SOPS. | Git history itself becomes the backup. |
| **PVC + auto-generated key** | Persistent volume claim mounted at `PrivateKeyDirectory`; key was auto-generated on first boot (Development-only — production refuses to start without provisioned keys). | The PV snapshot. |

The first two patterns are the most common in real production. The runbook entries
below are organised by **secret store**, not deployment pattern, because the backup
mechanism is owned by the secret store.

---

## Per-platform backup procedures

Pick the section that matches your secret store. If multiple apply (e.g. you store
keys in Vault and also have Velero backing up the K8s cluster), the secret-store-native
mechanism is the authoritative one — treat the other as a secondary safety net.

### Azure Key Vault

**Storage shape:** one secret per signing key. Recommended naming: `auth-signing-key-<kid-suffix>`
(the active key marker goes in a separate secret, e.g. `auth-signing-key-active-kid`).

**Backup is automatic when soft-delete + purge protection are on:**

```bash
az keyvault update --name <vault-name> \
  --enable-soft-delete true \
  --enable-purge-protection true
```

With purge protection, deleted secrets are recoverable for the configured retention
window (90 days default). This handles the most common loss scenario (someone deletes
the wrong secret) without any operator action.

**Additional belt-and-braces — full vault backup:**

```bash
az keyvault secret backup \
  --vault-name <vault-name> \
  --name auth-signing-key-<kid-suffix> \
  --file ./auth-signing-key-<kid-suffix>.backup
```

Store the `.backup` blob in a separate secured location (different subscription, or
cold storage). Run this on a schedule via Azure Automation or a CI job — once a week is
typically enough given the rotation cadence (quarterly).

**Restore (single secret):**

```bash
az keyvault secret restore \
  --vault-name <vault-name> \
  --file ./auth-signing-key-<kid-suffix>.backup
```

Then verify the CSI driver / Workload Identity wiring still points at the right vault
and secret name; pod restart picks up the restored secret on its next reconcile.

### AWS Secrets Manager

**Storage shape:** one secret per signing key. Use the binary secret type — PEM bytes
go in as-is, no base64 wrapping.

**Backup is automatic** via the deletion-recovery window (`--recovery-window-in-days`
on `delete-secret`, default 30 days, max 30). A "deleted" secret can be restored within
that window:

```bash
aws secretsmanager restore-secret \
  --secret-id auth-signing-key-<kid-suffix>
```

**For cross-region resilience**, replicate to a secondary region:

```bash
aws secretsmanager replicate-secret-to-regions \
  --secret-id auth-signing-key-<kid-suffix> \
  --add-replica-regions Region=eu-west-2
```

A regional outage no longer means key loss — point the pod at the secondary region's
secret manager.

**For long-term cold archive**, export periodically into S3 with object-lock retention:

```bash
aws secretsmanager get-secret-value \
  --secret-id auth-signing-key-<kid-suffix> \
  --query SecretBinary --output text \
  | base64 -d \
  | aws s3 cp - s3://<archive-bucket>/auth-keys/$(date -u +%Y%m%d)/auth-signing-key-<kid-suffix>.pem
```

Set bucket-level object lock to prevent accidental / malicious deletion of the archive.

**Alternative — AWS KMS:** if your security model wants the *key never to leave the
HSM*, store the signing key in KMS instead and have the auth service call KMS to sign.
This requires code changes (a `KmsSigningCredentials` adapter) and is out of scope here
— flagged for completeness.

### HashiCorp Vault

**Storage shape:** `kv-v2` secret engine, one key version per signing key. The
active-key marker lives at a separate path.

**Backup is via Raft snapshot** (if Vault is running in integrated-storage / Raft mode):

```bash
vault operator raft snapshot save raft-$(date -u +%Y%m%dT%H%M%S).snap
```

Run on a schedule; ship the snapshot to a separate location (S3 with object lock, an
Azure blob with immutability, etc.). The snapshot is a complete point-in-time backup of
every secret in the cluster — restore brings them all back together.

**For Consul-backed Vault**, use the Consul snapshot tool instead:

```bash
consul snapshot save consul-$(date -u +%Y%m%dT%H%M%S).snap
```

**Restore (full cluster from snapshot):**

```bash
vault operator raft snapshot restore raft-<timestamp>.snap
```

This is a heavy operation — it restores **every** secret in the cluster. For
single-secret recovery, use Vault's version history instead: `kv-v2` retains the
configured number of versions, and `vault kv rollback -version=<n>` brings a single
secret back without disturbing the rest of the cluster.

**For high-stakes deployments**, run Vault in HA mode across multiple regions; key loss
then requires losing every node in every region, which is the same failure profile as
losing the underlying cloud.

### Google Secret Manager

**Storage shape:** one secret per signing key, with one or more versions per secret.

**Backup is automatic** via version history — every update to a secret creates a new
version; old versions are retained indefinitely unless explicitly destroyed.

```bash
# Capture the current version (manual point-in-time)
gcloud secrets versions list auth-signing-key-<kid-suffix>

# Restore an older version (becomes the new "latest")
gcloud secrets versions access <version-number> \
  --secret=auth-signing-key-<kid-suffix> \
  --out-file=./recovered.pem

# Then upload as a new version of the same secret
gcloud secrets versions add auth-signing-key-<kid-suffix> \
  --data-file=./recovered.pem
```

**For cross-region archive**, set the secret's `replication.userManaged.replicas` to
include a secondary region.

**For cold archive outside Secret Manager**, the `access` command output above is the
PEM bytes — write to a GCS bucket with object versioning + bucket lock.

### Kubernetes Secrets (no external store)

Less ideal than any of the above — the Secret lives in `etcd`, and your backup story
is the `etcd` backup story. Treat as a stopgap rather than the long-term answer.

**Backup via Velero** (the standard K8s backup tool):

```bash
velero backup create auth-keys-$(date -u +%Y%m%dT%H%M%S) \
  --include-namespaces auth \
  --include-resources secrets \
  --selector app=authentication-service
```

Velero ships the backup to object storage (S3 / Azure Blob / GCS); restore brings the
Secret object back into the cluster.

**Manual fallback** (no Velero):

```bash
kubectl get secret auth-signing-keys -n auth -o yaml > auth-signing-keys-$(date -u +%Y%m%dT%H%M%S).yaml
```

`kubectl apply -f <file>` restores. Store the YAML file the same way you'd store any
other secret — it contains base64-encoded key material, not encrypted.

### Sealed Secrets / SOPS (git-managed)

Both options encrypt the PEM bytes at rest with a controller key, commit the
encrypted blob to git, and decrypt at deploy time.

**Backup is git itself.** As long as the repo is mirrored to at least one other host
(GitHub + a separate mirror, or git + a forge with offsite replication), key loss
requires losing every git remote — same failure profile as the rest of the codebase.

**The crucial second backup:** the **controller's private key** (Sealed Secrets'
sealing key, or SOPS' age/PGP/KMS key). Without it the encrypted blobs in git are just
opaque bytes. Back up the controller key the same way you'd back up any other
high-value secret — typically into one of the secret stores above.

```bash
# Sealed Secrets: dump the sealing key
kubectl get secret -n kube-system \
  -l sealedsecrets.bitnami.com/sealed-secrets-key=active \
  -o yaml > sealed-secrets-sealing-key-backup.yaml
```

**Restore:** redeploy from git (PEMs come back decoded into a normal K8s Secret), then
verify by JWT round-trip (below).

### Filesystem snapshots (last resort)

If for whatever reason there's no secret store in the picture and PEMs live on a PVC,
the only backup option is the underlying volume's snapshot mechanism (CSI snapshots,
EBS snapshots, Azure Disk snapshots, etc.). This is fine as a stopgap but loses the
audit trail / access controls / rotation tooling of a real secret store. Move to one
of the options above as soon as practical.

---

## Universal restore procedure

Regardless of which platform-specific section you used to recover the bytes, the same
universal steps complete the restore:

1. **Place the recovered PEM(s) into `JWTSettings:PrivateKeyDirectory`** on the
   auth-service pod. Mechanism depends on the deployment pattern (CSI driver re-projects
   automatically when the underlying secret changes; init-container deployments need a
   pod restart; Kubernetes Secret mounts need either the kubelet's projected-volume
   refresh interval to elapse or a pod restart).

2. **Set `JWTSettings:ActiveKeyId`** to the kid of the key that should sign new tokens.
   For routine restore this is whatever was active before the loss; for "all keys lost"
   it's the new key (see next section).

3. **Restart the auth service** (or wait for the projected-volume refresh, if you trust
   that path on your platform). Watch the startup logs for one
   `Loaded ES256 signing key <kid> from '<path>'` line per recovered key, plus
   `Active signing key is <kid>` for the one you marked active.

4. **Verify by JWT round-trip.** Hit `POST /api/Authentication/login` with a known
   credential, then `GET /.well-known/openid-configuration` to get the JWKS endpoint,
   then validate the returned token's signature against the JWKS using any JWT library.
   If it validates, the restore is correct end-to-end.

5. **Confirm the JWKS includes every recovered key.** `curl https://<auth-host>/.well-known/jwks` —
   you should see one entry per recovered PEM. Missing entries mean a PEM didn't load
   (check pod startup logs for parse errors).

---

## "All keys lost" runbook

The pathological case: every backup mechanism failed (ransomware, region-wide
catastrophe, mass deletion of secrets). The service refuses to start with an empty
`PrivateKeyDirectory` outside Development.

**Accept the consequences before you start.** Every issued token — access, refresh,
service-to-service — is now invalid. Every user has to log in again. Every consuming
service will see 401s on calls authenticated with the old keys until its JWKS cache
refreshes.

1. **Communicate first.** Tell the consumer-service teams what's happening and when to
   expect the new keys live, BEFORE you provision them. Their alerts will start firing
   the moment you cut over; a 5-minute heads-up prevents a noisy escalation chain.

2. **Provision a fresh key.** Follow [deployment.md §1](deployment.md#1-generate-the-signing-key)
   to generate a new ES256 PEM. This is the same procedure as initial provisioning.

3. **Inject into your secret store** of choice using the relevant section above. Set
   `JWTSettings:ActiveKeyId` to the new key's kid.

4. **Start the auth service.** Verify by JWT round-trip per the universal restore
   procedure step 4.

5. **Tell consumers to refresh their JWKS caches**, OR (faster) bounce their pods. The
   default `JwtBearer` cache TTL is 24 hours — without action, that's how long the 401
   storm lasts.

6. **Communicate completion.** "Auth back up, please re-authenticate / refresh JWKS
   caches if you haven't already."

7. **Post-incident**: figure out *why* every backup failed and fix the gap. The whole
   point of this doc is to prevent this scenario; if you've reached step 7 it means
   something in the prevention plan didn't work.

---

## Restore-test cadence

**The only restore that counts is the one you've actually performed.** Schedule a
restore drill at least quarterly. The drill:

1. Spin up a non-prod auth-service instance (staging, ephemeral test env — anywhere
   real that isn't actually serving traffic).
2. Restore yesterday's backup into it using whichever platform section applies.
3. Mint a token via login.
4. Validate the token against the restored instance's JWKS endpoint.
5. Capture how long the whole thing took. Compare to last quarter's number — if it's
   getting longer over time, something is drifting in the procedure and now is the time
   to fix it, not at 2am during a real incident.

If a drill fails, the drill is the highest-priority work item for the next day. Don't
let "the procedure didn't work in staging" sit in a quarterly review log.

---

## Cross-references

- [`key-rotation.md`](key-rotation.md) — routine rotation runbook (not the same as
  restore-from-loss).
- [`deployment.md`](deployment.md) — initial key generation.
- `AuthenticationService/Services/EcdsaKeyProvider.cs` — the loader. Reads every
  `*.pem` in `PrivateKeyDirectory`; derives the kid from the JWK thumbprint;
  `ActiveKeyId="auto"` picks the first key found.
- `AuthenticationService/Settings/JWTSettings.cs` — config schema.
