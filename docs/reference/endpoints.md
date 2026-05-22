# Endpoint reference

Quick lookup for what's exposed. Full Swagger lives at `https://localhost:<port>/swagger`.

## Authentication

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/Authentication/authenticate` | None | Login (returns token or "MFA required") |
| `POST /api/Authentication/mfa` | None | Submit MFA code, receive token |
| `POST /api/Authentication/refresh` | Expired bearer + refresh body | Rotate to a new pair. Reuse of a consumed refresh token revokes every session for the user (cascade). |
| `POST /api/Authentication/logout` | Bearer | Revoke this device's session. Other devices keep working. |
| `POST /api/Authentication/logoutall` | Bearer | Revoke every session for the user + rotate the security stamp. |

## Registration

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/Registration/register` | None | Create account |
| `GET /api/Registration/confirm/email` | None | Confirm email via the link sent at registration |
| `POST /api/Registration/confirm/email` | None | Resend the confirmation email |
| `POST /api/Registration/accept-invitation` | None | Accept an admin-issued invitation; user sets their initial password |

## Account self-service

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/Account/me` | Bearer | Current user's profile + roles, read live from the DB. Useful for SPA UI rendering and as a "is my token still good?" diagnostic. |
| `PUT /api/Account/me` | Bearer | Update non-sensitive profile fields. Phone changes reset phone-confirmed. |
| `POST /api/Account/changepassword` | Bearer | Change password while authenticated. Identity is read from the token's `sub`. |
| `POST /api/Account/forgotpassword` | None | Request a password-reset email. Also clears any active lockout on successful reset. |
| `POST /api/Account/forgotpassword/reset` | None | Apply the reset using the email-link token. |
| `GET /api/Account/enablemfa` | Bearer | Enable MFA in one call: flips `MfaEnabled = true` on the user AND returns the shared secret + QR code (authenticator) or verification details (email / phone). There is no separate "confirm" endpoint — the first successful login under MFA proves possession. |
| `POST /api/Account/lock` | Email-link token | Triggered from the "wasn't you?" link in password-changed emails — locks the account and sends a reset link. |

## Admin

All admin endpoints require `[Authorize(Policy = AdminOnly)]`.

| Endpoint | Purpose |
|---|---|
| `GET /api/Admin/users` | Paginated list of users; filterable by search, locked, unconfirmed. |
| `GET /api/Admin/users/{id}` | User detail. |
| `POST /api/Admin/users` | Admin creates a user → invitation email sent. |
| `POST /api/Admin/users/{id}/resend-invitation` | Re-send the invitation email. |
| `POST /api/Admin/users/{id}/lock` | Lock the account indefinitely. |
| `POST /api/Admin/users/{id}/unlock` | Clear lockout + failed-attempt counter. |
| `POST /api/Admin/users/{id}/revoke-sessions` | Revoke every refresh-family + rotate security stamp. |
| `POST /api/Admin/users/{id}/reset-mfa` | Disable MFA on the user's account. |
| `POST /api/Admin/users/{id}/force-password-reset` | Trigger reset email, revoke refresh tokens. |
| `GET /api/Admin/users/{id}/audit` | SecurityEvent audit log for the user. |
| `POST /api/Admin/clients` | Create s2s client. **Response carries one-time-display secret.** |
| `GET /api/Admin/clients` | List clients. |
| `GET /api/Admin/clients/{id}` | Client detail (no secret). |
| `POST /api/Admin/clients/{id}/rotate-secret` | New one-time-display secret. |
| `POST /api/Admin/clients/{id}/disable` | Soft-delete (sets `IsDisabled`). |
| `POST /api/Admin/clients/{id}/scopes` | Add a `(audience, scope)` tuple. |
| `DELETE /api/Admin/clients/{id}/scopes/{audience}/{scope}` | Remove a scope. |

## OAuth / discovery

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /oauth/token` | Basic auth (client_id : client_secret) | RFC 6749 §4.4 client-credentials grant. Returns a service-identity JWT. |
| `GET /.well-known/openid-configuration` | None | OIDC discovery doc (advertises `token_endpoint`, `grant_types_supported`, `jwks_uri`). |
| `GET /.well-known/jwks.json` | None | Public signing keys for JWT validation. |

## Health

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /livez` | None | Liveness probe. 200 if the process is up. |
| `GET /readyz` | None | Readiness probe. 200 if MySQL + Redis reachable. |
| `GET /healthz` | None | Combined detail. For human consumption / dashboards. |

## Test / smoke

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/Test` | Admin | Smoke test (admin policy). |
| `GET /api/Test/all` | Authenticated | Smoke test (any user). |
