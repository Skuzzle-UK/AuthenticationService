# Refresh-token rotation + reuse cascade

How the refresh-token lifecycle works, and what happens when a (presumably stolen) consumed token is replayed.

## Rotation

Every successful `POST /api/Authentication/refresh` does three things atomically:

1. Validates the presented refresh-token hash against `RefreshTokens` (must exist, not consumed, not expired).
2. **Stamps `ConsumedAt`** on the existing row (single UPDATE with a `WHERE consumed_at IS NULL` guard — see "race protection" below).
3. **Inserts a new row** with the same `FamilyId`, a fresh `Id`, a fresh hash. The old row is updated to point at the new one via `ReplacedByTokenId`.

The response carries a new access token + new refresh token. The client is expected to discard the previous refresh token immediately.

## Reuse-cascade (theft detection)

If a refresh request arrives with a refresh token that is already `ConsumedAt`-stamped, **someone has the wrong token**. Either:

- The legitimate client failed to discard the old token (a bug), or
- An attacker who stole the original token is replaying it after the legitimate client has already rotated past it.

The auth service can't distinguish these two cases. It treats both as theft:

1. **Every active refresh-token family** for the user is revoked — not just the offending one. The attacker may have other tokens in flight; nuke them all.
2. **The user's security stamp is rotated.** ASP.NET Core Identity's security stamp is baked into the access-token's claims (indirectly via `ValidateSecurityStampAsync` checks). Rotating it instantly invalidates every outstanding access token, across every device.
3. **A "suspicious activity" email** is sent to the user with a reset link.
4. **SIEM event** `RefreshTokenReuseDetected` (event ID 1008, Critical) is logged.

The legitimate user finds out via the email, hits the reset link, sets a new password, signs back in fresh. The attacker's tokens are dead.

## Race protection

The "stamp ConsumedAt + insert new row" pair needs to be atomic. Without that, two simultaneous refresh requests with the same valid refresh token could both succeed, and the reuse-cascade never fires.

The implementation uses a **single SQL UPDATE statement with a `WHERE consumed_at IS NULL` guard**, plus an `ExecuteUpdateAsync` returning the row-count. Only one of the racing requests gets a non-zero rowcount; the other gets zero, treats it as reuse, and triggers the cascade. See `JWTService.RotateRefreshTokenAsync` for the implementation.

## ReplacedByTokenId

After a successful rotation:

- Old row: `ConsumedAt = now`, `ReplacedByTokenId = <new row's Id>`.
- New row: fresh `Id`, same `FamilyId`, `ConsumedAt = null`.

The `ReplacedByTokenId` back-pointer makes the chain walkable forward. It's mostly diagnostic — reuse detection doesn't depend on it (the simple `ConsumedAt IS NOT NULL` check is sufficient) — but it's useful for forensic queries:

```sql
-- Trace the full rotation chain for a session family
SELECT Id, CreatedAt, ConsumedAt, ReplacedByTokenId
FROM RefreshTokens
WHERE FamilyId = '...'
ORDER BY CreatedAt;
```

## Logout interactions

| Logout flavour | Effect |
|---|---|
| `POST /api/Authentication/logout` | Revokes the caller's current family only. The access token is added to the `RevokedTokens` deny-list so the next call with it returns 401. Other devices keep working. |
| `POST /api/Authentication/logoutall` | Revokes every refresh-token family for the user + rotates the security stamp. Every outstanding access token across every device dies on next validation. |

The deny-list is checked by `RevokedTokenMiddleware` on every authenticated request before the controller runs. See [concepts/security-model.md](security-model.md#revoked-token-deny-list).

## What an attacker actually sees

- Steals a refresh token (somehow — XSS, leaked logs, compromised local storage).
- Uses it before the legitimate client rotates → gets a fresh access+refresh pair → starts replaying access tokens. The auth service's deny-list catches access-token replay (the legitimate client's rotation puts the access token on the deny-list when its refresh consumes), but the new family is the attacker's now.
- Uses it *after* the legitimate client rotates → the consumed token triggers the cascade above → every family revoked → suspicious-activity email → security stamp rotated → all the attacker's tokens die.

The win for defenders is the **mandatory cascade**: there's no "try again with the new token" path. The first successful rotation is the only one that succeeds; every subsequent attempt against the same family triggers full revocation.

The window where the attacker can act undetected is bounded by:
- 5 minutes (access-token TTL), if they only have an access token, OR
- The time until the legitimate client next refreshes (typically minutes), if they have a refresh token

After that, either the attacker's token expires (access) or the cascade fires (refresh).

## Integration test coverage

This flow is covered end-to-end against real MySQL by **integration scenario 3** (`RefreshTokenReuseCascadeTests.SecondRefreshWithConsumedToken_TriggersFullCascadeAndNotifiesUser`). See [development/testing.md](../development/testing.md).
