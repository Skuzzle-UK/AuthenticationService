# Admin account recovery

If the seeded administrator account is locked out, has lost its MFA device, or the
password is genuinely lost, there are **three documented ways to recover it**, in
order of operational invasiveness:

| # | Option | When to use | Audit trail |
|---|---|---|---|
| 1 | Raw SQL (DB-only fields) | Quick fix for lockout / MFA / email-confirmed flags when you have DB access but the service is otherwise healthy. **Can't reset the password** — passwords are hashed and Identity won't accept a hash you compute outside it. | Manual — `SecurityEvent` row will NOT be written. Note the change in your ops log. |
| 2 | `dotnet run -- reset-admin` (CLI) | Service binary is reachable; you want password reset + all the trimmings in one go. Doesn't restart the running pod. | `SecurityEventIds.AdminAccountRecovered` (5100) at Critical. |
| 3 | `AdminAccountSeedSettings:ResetOnStartup=true` (env var + restart) | You're already restarting the pod (deploy, cert rotation, etc.) and want recovery to ride along. Or the binary isn't directly invocable and you can only nudge config. | `SecurityEventIds.AdminAccountRecovered` (5100) at Critical. |

All three converge on the same end state: the seeded admin can log in with the
password from `AdminAccountSeedSettings:Password`, MFA is off, lockout is cleared,
existing sessions are revoked.

---

## Before you start (all options)

1. **Decide on the new password.** Set it in env / secret store as
   `AdminAccountSeedSettings__Password` (`__` is the .NET config separator —
   `:` works in some platforms but `__` is portable across all of them). It must
   satisfy `IdentitySettings:Password.*` policy or the reset will refuse.
2. **Have shell access** to a machine that can reach the auth DB (options 1 + 2)
   or pod-restart authority (option 3).
3. **Brief the team.** Recovery emits a Critical-level audit event — make sure
   whoever monitors SIEM knows it's an expected operator action, not an attack.

---

## Option 1 — Raw SQL (clear lockout / MFA / email-confirmed only)

The narrowest tool. Use it when you don't need to reset the password — e.g. the
admin is locked out from failed login attempts but the password itself is fine.

> **Cannot reset the password this way.** ASP.NET Identity stores password hashes
> in a specific format (`{version}.{iterations}.{salt}.{hash}`) and validates them
> against `PasswordHasher`. There is no portable "set the hash from raw SQL"
> recipe that survives Identity version changes. If you need to reset the
> password, use **Option 2** or **Option 3**.

Find the admin user ID first:

```sql
SELECT Id, UserName, LockoutEnd, AccessFailedCount, EmailConfirmed,
       TwoFactorEnabled, SecurityStamp
FROM AspNetUsers
WHERE UserName = 'admin';
```

Clear lockout + failed-attempt counter:

```sql
UPDATE AspNetUsers
SET LockoutEnd = NULL,
    AccessFailedCount = 0
WHERE UserName = 'admin';
```

Disable MFA (so the operator can log in without the authenticator app):

```sql
UPDATE AspNetUsers
SET TwoFactorEnabled = 0
WHERE UserName = 'admin';
```

Re-confirm the email (if somehow it got flipped off):

```sql
UPDATE AspNetUsers
SET EmailConfirmed = 1
WHERE UserName = 'admin';
```

Revoke all active refresh tokens (forces the admin to log in fresh on every
device — useful if you suspect compromise):

```sql
UPDATE RefreshTokens
SET ConsumedAt = UTC_TIMESTAMP(6),
    RevocationReason = 'admin_recovery'
WHERE UserId = (SELECT Id FROM AspNetUsers WHERE UserName = 'admin')
  AND ConsumedAt IS NULL;
```

Rotate the security stamp (kills any still-live access tokens immediately, since
the JWT bearer middleware re-checks the stamp on every request):

```sql
UPDATE AspNetUsers
SET SecurityStamp = UUID()
WHERE UserName = 'admin';
```

**No SIEM row is written.** Note the change in your ops log book or
incident ticket so it's reconstructable later.

---

## Option 2 — CLI subcommand (full reset, no restart)

The most operationally honest choice. Run from any machine that has the
`AuthenticationService` binary and access to the DB.

```bash
# On Linux / macOS
export AdminAccountSeedSettings__Password='ChooseAStrongOne!'
dotnet run --project AuthenticationService -- reset-admin
```

```powershell
# On Windows PowerShell
$env:AdminAccountSeedSettings__Password = 'ChooseAStrongOne!'
dotnet run --project AuthenticationService -- reset-admin
```

What it does:

1. Builds the same DI graph as the running service (same connection strings,
   same password policy validators).
2. Looks up the seeded admin by username (`admin`).
3. Clears lockout + access-failed counter.
4. Re-confirms email if not already confirmed.
5. Resets password via `UserManager.ResetPasswordAsync` — goes through the
   `CustomPasswordValidator` policy, so weak passwords are rejected.
6. Disables MFA (`TwoFactorEnabled = false`). Authenticator key is left in
   place; if the operator re-enables MFA later, the existing key still works
   (or they can rotate it from `/Account/Me`).
7. Re-ensures Admin + DefaultUser role membership.
8. Revokes every active refresh token for the admin (`reason: admin_recovery`).
9. Rotates the security stamp.

**Emits:** one `SecurityEventIds.AdminAccountRecovered` (5100) event at Critical
level. SIEM should page on this — it's a deliberately loud event for an
out-of-band privileged operation.

**Exit codes:**
- `0` — reset succeeded (or admin doesn't exist and a warning was logged).
- Non-zero — exception propagated; check the console output. The most common
  failure is "password doesn't meet policy" — adjust the value and re-run.

**The running production pod is not affected.** It keeps serving requests. The
admin just needs to log in with the new credentials.

---

## Option 3 — `ResetOnStartup` flag (recovery on next restart)

Use when you're already rolling the pod (cert rotation, config push, etc.) and
want the reset to land in the same window — no separate operator action needed.

1. Set both:
   ```
   AdminAccountSeedSettings__Password=ChooseAStrongOne!
   AdminAccountSeedSettings__ResetOnStartup=true
   ```
2. Restart the pod. On startup the seeder logs:
   ```
   AdminAccountSeedSettings:ResetOnStartup is enabled — applying recovery reset
   to admin. Unset the flag before the next restart or every restart will keep
   resetting the admin.
   ```
   …then runs the same reset as Option 2.
3. **Important:** unset `ResetOnStartup` (or set it to `false`) and restart the
   pod a second time. If you leave the flag on, every subsequent restart will
   re-reset the admin — surprising and noisy.

The audit event (`AdminAccountRecovered` 5100) is emitted on every restart while
the flag is on. SIEM will page on each occurrence, which is part of the design
— it makes "we forgot to unset the flag" very obvious.

---

## After recovery (all options)

1. Log in as `admin` with the new password.
2. Re-enrol MFA from `/Account/Me` — the previous authenticator secret was left
   in place by Option 2/3 but you should rotate it on principle since it was
   live while the account was in an unknown state.
3. Confirm the audit trail:
   ```sql
   SELECT TimestampUtc, EventId, Message
   FROM SecurityEvents
   WHERE EventId = 5100
   ORDER BY TimestampUtc DESC
   LIMIT 5;
   ```
   The `AdminAccountRecovered` row should match your operator action.
4. **Rotate the value in `AdminAccountSeedSettings:Password`.** The password you
   just set is now the bootstrap password for any future seeded environment and
   any future recovery — treat it like any other shared secret.

---

## When none of these work

- **Forgot the admin username?** It's the constant `admin` — see
  `AuthenticationService.Constants.UserConstants.Admin`.
- **DB connection from the recovery machine fails?** Options 2 and 3 both
  need DB access. Option 1's SQL can be run from anywhere that has DB access
  via a different client.
- **`AdminAccountSeedSettings:Password` policy still rejects your value?**
  Check `IdentitySettings:Password.*` in the same appsettings — the recovery
  goes through the live policy validators.
- **The admin account was deleted somehow?** Recovery only resets existing
  accounts. Set `ResetOnStartup` to `false`, leave `Password` configured,
  delete any row for `UserName = 'admin'` (if it exists), restart — the
  seeder will create it from scratch.
