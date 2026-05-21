# User authentication flows

End-user perspective: what the API surface looks like to a SPA / mobile app / native client signing real humans in and out.

## The happy path

1. **Register** with email + password. Username is a separate display field; a deny-list (`IdentitySettings.User.ReservedUserNames` in config) blocks claims on names that should remain reserved for system / platform identities (`administrator`, `root`, `noreply`, `support`, etc.).
2. **Confirm email** via the link sent to the inbox.
3. **Authenticate** with email/username + password — receive a JWT (5 min) + refresh token (5 days). The pair belongs to a "session family" identified by the `sid` claim — a single login is one family; multiple devices each get their own.
4. (Optional) **Enable MFA** — server returns a QR code.
5. With MFA enabled: authenticate with credentials → server returns "MFA required" → submit MFA code → receive token.
6. **Refresh** before expiry. Each refresh issues a new pair and *immediately consumes* the presented refresh token. See [refresh-rotation.md](refresh-rotation.md) for the reuse-cascade story.
7. **Logout (per device)** revokes the caller's session family and adds the current access token to the deny-list. Other devices the user is signed in on are unaffected.
8. **Logout-all** revokes every session family for the user and rotates the security stamp — all outstanding access tokens die immediately.
9. **Account locked or password forgotten?** The `forgotpassword` flow is the unlock path too — a successful reset clears any active lockout.

## Session-family model

Every successful login mints a `(access token, refresh token)` pair that share a **`FamilyId`** (a GUID). The same `FamilyId` is stamped into:

- The refresh-token row in `RefreshTokens` (DB).
- The access-token's `sid` claim.

Subsequent refreshes within the same login session reuse the `FamilyId` — the old refresh row gets `ConsumedAt` stamped and a new row is created in the same family, pointing back via `ReplacedByTokenId`. A user with multiple devices has one family per device.

This is what makes per-device logout work cleanly: revoke just one family and the other devices keep working. Logout-all rotates the user's security stamp, which invalidates every outstanding access token across every family.

## MFA shape

MFA is opt-in per user, enrolled via `GET /api/Account/enablemfa` (returns a QR for an authenticator app) and `POST /api/Account/enablemfa` (submits the first code to confirm enrolment).

Three providers are recognised in code (`MfaProviders` enum):

| Provider | Status |
|---|---|
| `Authenticator` | Fully implemented. TOTP via the standard apps (Authenticator, Authy, 1Password). |
| `Email` | Fully implemented. One-time code emailed to the confirmed address. |
| `Phone` | **Not configured.** The default `ISmsService` registration (`NotConfiguredSmsService`) reports `IsConfigured = false` and the endpoints return a clean `BadRequest` if the user picks Phone. To enable: implement `ISmsService` against your provider (Twilio, AWS SNS, MessageBird, …) and replace the registration in `HostExtensions.AddServices`. A phone-number confirmation flow needs building first — see TODO. |

After MFA is enabled, the `/authenticate` response carries `{ mfaRequired: true, mfaProviders: [...] }` instead of a token. The client picks a provider and submits the code via `POST /api/Authentication/mfa` to receive the token.

## Lockout & recovery

Three different code paths can lock a user out. **All three converge on the same recovery flow** — `/ResetPassword` page → `POST /api/Account/forgotpassword/reset` → on success, `LockoutEnd` is cleared, the failed-attempt counter is reset, every refresh-token family is revoked, and the user is logged in fresh on next sign-in.

| Lock cause | Trigger | How the user finds out | Recovery |
|---|---|---|---|
| **Failed-login lockout** | N consecutive bad passwords (Identity's `MaxFailedAccessAttempts`, default 3) | Email: "Account locked due to failed attempts" | User starts `/forgotpassword` themselves → email link → `/ResetPassword` |
| **Panic-button lock** | User clicks "wasn't me!" link in the password-changed email | The lock email tells them what just happened | User clicks the reset link in the *same* email → `/ResetPassword` |
| **Threshold-escalation lock** | Sustained replay of a revoked token (5 hits in 5 min, default) — see [security-model.md](security-model.md#threshold-escalation) | Email: "Suspicious activity, account locked, here's a reset link" | User clicks the link in the lock email → `/ResetPassword` |

Why this matters: the `/ResetPassword` page is generic — it doesn't need to know *why* the user's there, and the controller endpoint behind it clears the lockout regardless of cause. So when a future lockout mechanism is added (e.g. an admin-initiated lock), the recovery story is already wired — emit a reset link in the notification email, point it at `/ResetPassword`, done. **Don't build per-cause recovery pages.**

## Email confirmation & data-protection tokens

Registration → confirm-email → password-reset all use ASP.NET Core Identity tokens, which are signed by the Identity data-protection key ring. The key ring is **persisted to Redis** so the same token can be redeemed by any replica of the auth service, and it survives restart.

See [operations/deployment.md §3](../operations/deployment.md#3-provision-redis) for the Redis persistence requirements — without persistence configured, every replica restart breaks every outstanding email-link token.

## Open items

- **SMS/phone MFA** — implement an `ISmsService` against your provider; a phone-number confirmation flow needs adding to mirror email confirmation.
- **External IdP / SSO** — sign in with Microsoft / Google / Entra. Not yet implemented; tracked in [`TODO.md`](../../TODO.md).
