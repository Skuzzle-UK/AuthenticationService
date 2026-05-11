# Admin Endpoints — Implementation Plan

**Status:** Draft, not yet started
**Estimated effort:** ~2 focused days (originally scoped at 1.5; admin-creates-user invitation flow + basic page adds ~half a day)
**Tier:** 5 (multi-tenant features) / Phase 0 of [`service-to-service-auth-plan.md`](service-to-service-auth-plan.md)
**Last updated:** 2026-05-11

---

## Why we're building this

Today the auth service has no operational surface. The seeded `admin` account exists, `[Authorize(Policy = "AdminOnly")]` is wired up, and a single `TestController` endpoint sits behind it as a placeholder. Everything else — locking a misbehaving user, clearing MFA for someone who lost their phone, revoking sessions on suspicion of compromise — has to be done by hand against the database. That's the kind of thing that gets done at 2am during an incident, with all the risk that implies.

Phase 0 stands up a proper admin endpoint surface. It also lays the foundation for Phase 1 (service-to-service auth) which needs client-management endpoints — those will be added to the same `AdminController` once Phase 0 is in.

---

## Endpoint summary

| Endpoint | Purpose |
|---|---|
| `GET /api/Admin/users` | Paginated list of users (filter by search / lockedOnly / unconfirmedOnly) |
| `GET /api/Admin/users/{id}` | Full user detail including roles, MFA, lockout, active session count |
| `POST /api/Admin/users` | **Create a user; sends invitation email; user sets their own password on first visit** |
| `POST /api/Admin/users/{id}/resend-invitation` | Re-send invitation email when token expires (24h TTL) |
| `POST /api/Admin/users/{id}/lock` | Lock account indefinitely |
| `POST /api/Admin/users/{id}/unlock` | Lift active lockout, reset access-failed counter |
| `POST /api/Admin/users/{id}/revoke-sessions` | Revoke all refresh-token families + rotate stamp + revoke access token |
| `POST /api/Admin/users/{id}/reset-mfa` | Disable MFA, clear authenticator key, revoke sessions |
| `POST /api/Admin/users/{id}/force-password-reset` | Generate password-reset link, email it, revoke sessions |
| `GET /api/Admin/users/{id}/audit` | Recent security events for the user (paginated, filterable by date) |

Plus the new public-facing endpoint for users completing their invitation:

| Endpoint | Purpose |
|---|---|
| `POST /api/registration/accept-invitation` | Set initial password + confirm email in one step (token-gated) |

---

## Confirmed design decisions

Settled with the project owner (2026-05-11):

| # | Decision | Choice | Notes |
|---|---|---|---|
| 1 | Route prefix | `/api/Admin/*` | Matches existing controller convention; clean grep target |
| 2 | List filters | `search` + `lockedOnly` + `unconfirmedOnly` | All three; cheap to implement |
| 3 | `pageSize` cap | 100 | Default 20; clamp >100 to 100 |
| 4 | `reset-mfa` side-effects | Revoke sessions implicitly | Defence-in-depth wins over endpoint orthogonality |
| 5 | `force-password-reset` flavour | Email reset link, reuse existing user flow | Smaller surface, admin never sees the password |
| 6 | Audit data source | Serilog SQL sink alongside file/console | No fork in emit path; piggy-backs on SIEM pipeline |
| 7 | Admin self-protection | Reject all destructive ops on self | Prevents fat-fingering "lock admin" |
| 8 | Bulk operations | Defer to Phase 0.5 | Not day-one; incident-response shaped |
| 9 | Admin-creates-user endpoint | **Yes, with invitation flow** (see below) | Reuses password-reset token mechanism + new basic page |
| 10 | Role management endpoints | Defer to Phase 0.5 | Only Admin + DefaultUser exist today |

---

## Cross-cutting design

These apply to every endpoint in this plan unless stated otherwise.

- **Controller:** `Controllers/AdminController.cs`, new file. Service layer: `Services/IAdminService.cs` + `AdminService.cs`. Controller stays thin and delegates to the service (matches existing `AccountController` → `IUserService` split).
- **Auth:** `[Authorize(Policy = PolicyConstants.AdminOnly)]` at the controller level. Already wired; no new policy needed.
- **Rate limit:** `[EnableRateLimiting(RateLimitPolicies.AuthSensitive)]` at the controller level — per-user (the admin) 10/min. Tight enough that bulk fat-finger doesn't work; loose enough for real ops.
- **Response envelope:** existing `ApiResponse<T>` for single-object responses. New `PagedResponse<T>` for list endpoints (see below).
- **Audit:** every state-changing endpoint emits a new `SecurityEventIds.Admin*` event in the 5000–5999 range. See Security Events section.
- **Admin self-protection:** all destructive endpoints (`lock`, `revoke-sessions`, `reset-mfa`, `force-password-reset`) reject with `400 Bad Request` if `target.Id == currentAdmin.Id`. Listed/detail/audit endpoints work normally on self (admin can audit their own activity).
- **CSRF:** these are POST endpoints with Bearer auth — JWT-bearer is immune to CSRF; no anti-forgery tokens needed.
- **Idempotency:** `lock` / `unlock` / `reset-mfa` are idempotent — calling on an already-locked account refreshes the timestamp; calling unlock on an already-unlocked account is a no-op success. Documented in OpenAPI.

### New paginated envelope

```csharp
// AuthenticationService.Shared/Dtos/Response/PagedResponse.cs
public record PagedResponse<T>
{
    public required IReadOnlyList<T> Results { get; init; }
    public required int TotalCount { get; init; }
    public required int Page { get; init; }
    public required int PageSize { get; init; }
}
```

First use is `GET /api/Admin/users` + `GET /api/Admin/users/{id}/audit`. Phase 1 reuses for `GET /api/Admin/clients`.

### New security events (5000–5999 — admin actions)

```
5001 AdminLockedAccount
5002 AdminUnlockedAccount
5003 AdminRevokedSessions
5004 AdminResetMfa
5005 AdminForcedPasswordReset
5006 AdminCreatedUser
5007 AdminResentInvitation
```

Phase 1 will extend with `5101 AdminCreatedClient`, `5102 AdminRotatedClientSecret`, etc. — kept in the same range.

Plus one new event in the existing 2000s (Registration) range:
```
2004 InvitationAccepted        // user set initial password via invitation link
```

All admin events log `{AdminUserId}`, `{TargetUserId}`, `{IpAddress}` and any operation-specific fields.

### Audit data source — Serilog SQL sink

Add `Serilog.Sinks.MySql` (or whichever sink matches the chosen DB provider) alongside the existing file + console sinks. The existing `_logger.LogInformation(SecurityEventIds.X, ...)` calls keep working unchanged; the SQL sink picks up the structured fields (UserId, IpAddress, etc.) as typed columns.

`GET /api/Admin/users/{id}/audit` queries that table directly:

```sql
SELECT Timestamp, EventId, EventName, Properties_UserId, Properties_IpAddress, ...
FROM SecurityEventLog
WHERE Properties_UserId = @id
  AND Timestamp >= @since
ORDER BY Timestamp DESC
LIMIT @pageSize OFFSET @offset;
```

Sink config goes in `appsettings.json` alongside the existing Serilog config — no new emit-path code.

---

## Endpoint detail

### `GET /api/Admin/users`

**Query params:**
- `page` (int, default 1, min 1)
- `pageSize` (int, default 20, max 100)
- `search` (string, optional) — case-insensitive substring match on `UserName` OR `Email`
- `lockedOnly` (bool, default false) — `WHERE LockoutEnd > UTC_NOW()`
- `unconfirmedOnly` (bool, default false) — `WHERE EmailConfirmed = false`

**Response (200):** `PagedResponse<UserSummaryDto>` where `UserSummaryDto`:
```csharp
public record UserSummaryDto
{
    public required string Id { get; init; }
    public required string UserName { get; init; }
    public required string Email { get; init; }
    public required bool EmailConfirmed { get; init; }
    public required bool IsLocked { get; init; }
    public required bool MfaEnabled { get; init; }
    public required DateTime CreatedAt { get; init; }
}
```

**Implementation note:** `IsLocked` is computed (`u.LockoutEnd != null && u.LockoutEnd > DateTimeOffset.UtcNow`). `MfaEnabled` comes from `u.TwoFactorEnabled`. `CreatedAt` — currently the `User` entity doesn't have a `CreatedAt` field; **Phase 0 adds it** with a migration. Default for existing rows: the migration's apply timestamp.

### `GET /api/Admin/users/{id}`

**Response (200):** `ApiResponse<UserDetailDto>` where:
```csharp
public record UserDetailDto
{
    public required string Id { get; init; }
    public required string UserName { get; init; }
    public required string Email { get; init; }
    public required bool EmailConfirmed { get; init; }
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public DateOnly? DateOfBirth { get; init; }
    public string? PhoneNumber { get; init; }
    public bool PhoneNumberConfirmed { get; init; }
    public string? Country { get; init; }
    public string? AddressLine1 { get; init; }
    public string? AddressLine2 { get; init; }
    public string? AddressLine3 { get; init; }
    public string? City { get; init; }
    public string? Postcode { get; init; }
    public required LockoutInfoDto Lockout { get; init; }
    public required MfaInfoDto Mfa { get; init; }
    public required IReadOnlyList<string> Roles { get; init; }
    public required int ActiveRefreshTokenFamilies { get; init; }
    public required DateTime CreatedAt { get; init; }
}

public record LockoutInfoDto(bool IsLocked, DateTimeOffset? LockoutEnd, int AccessFailedCount, bool LockoutEnabled);
public record MfaInfoDto(bool Enabled, MfaProviders PreferredProvider);
```

`ActiveRefreshTokenFamilies` — `COUNT(DISTINCT FamilyId) WHERE UserId = @id AND ConsumedAt IS NULL AND ExpiresAt > UTC_NOW()`. Cheap, surfaces real per-user device count.

**404** if user not found.

### `POST /api/Admin/users` (invitation flow — see separate section below)

### `POST /api/Admin/users/{id}/resend-invitation`

Re-issues the invitation: generates a fresh password-reset token, re-sends the invitation email. Only works on users where `EmailConfirmed = false` AND `PasswordHash IS NULL` (i.e. still in pending-invitation state). Returns `409 Conflict` otherwise.

Emits `AdminResentInvitation` (5007).

### `POST /api/Admin/users/{id}/lock`

**Body:** none.
**Implementation:** mirrors `AccountController.cs:491-492`:
```csharp
await userManager.SetLockoutEnabledAsync(user, true);
await userManager.SetLockoutEndDateAsync(user, LockoutDurations.Indefinite);
```
**Response (200):** `ApiResponse<LockoutInfoDto>` reflecting the new state.
**Side effects:** does NOT revoke sessions automatically — locked users can't authenticate but existing sessions continue until their access tokens expire. If the admin wants those gone too, they call `revoke-sessions` separately. (Decision: explicit beats implicit here; "lock" is sometimes used as a temporary administrative hold where ongoing sessions are deliberately fine.)
**Audit:** `AdminLockedAccount` (5001).
**Idempotent.**

### `POST /api/Admin/users/{id}/unlock`

**Body:** none.
**Implementation:**
```csharp
user.LockoutEnd = null;
user.AccessFailedCount = 0;
await userManager.UpdateAsync(user);
```
**Response (200):** `ApiResponse<LockoutInfoDto>`.
**Audit:** `AdminUnlockedAccount` (5002).
**Idempotent.**

### `POST /api/Admin/users/{id}/revoke-sessions`

**Body:** none.
**Implementation:** delegates to the existing `IUserService.InvalidateUserTokensAsync(userId)` which:
1. Rotates the security stamp
2. Revokes all refresh-token families (`ITokenService.RevokeAllRefreshTokenFamiliesAsync`)
3. Revokes the current access token if one was presented

`reason` passed through as `"Admin revoked all sessions"`.
**Response (200):** `ApiResponse<string>` confirming.
**Audit:** `AdminRevokedSessions` (5003) — single emit at the admin level; the underlying revoke-all already emits its own `LogoutAllDevices` event. SIEM correlates the two by `{UserId}` + `{Timestamp}`.

### `POST /api/Admin/users/{id}/reset-mfa`

**Body:** none.
**Implementation:**
```csharp
await userManager.SetTwoFactorEnabledAsync(user, false);
await userManager.ResetAuthenticatorKeyAsync(user);
await userService.InvalidateUserTokensAsync(user.Id);   // implicit session revoke
```
**Response (200):** `ApiResponse<string>` confirming.
**Audit:** `AdminResetMfa` (5004).

### `POST /api/Admin/users/{id}/force-password-reset`

**Body:** optional `{ "callbackUri": "..." }`. If omitted, uses the default reset-password callback (`PublicUrlSettings.BaseUrl` + `PageRouteConstants.ResetPassword`).

**Implementation:**
1. Generate password reset token: `userManager.GeneratePasswordResetTokenAsync(user)`
2. Build reset URI via existing `AccountHelpers.GenerateResetPasswordUri(email, token, baseUri)`
3. Enqueue email via `IEmailService.SendEmailAsync` — re-use the existing forgot-password email body (or add a slight variant: "An administrator has initiated a password reset on your account..." — see open questions)
4. Revoke all sessions: `userService.InvalidateUserTokensAsync(user.Id)`

**Response (200):** `ApiResponse<string>` confirming.
**Audit:** `AdminForcedPasswordReset` (5005).

### `GET /api/Admin/users/{id}/audit`

**Query params:**
- `page` (int, default 1)
- `pageSize` (int, default 50, max 100)
- `since` (DateTime, optional, default = now - 30 days)
- `eventId` (int, optional, single-value filter)

**Response (200):** `PagedResponse<AuditEntryDto>`:
```csharp
public record AuditEntryDto
{
    public required DateTime Timestamp { get; init; }
    public required int EventId { get; init; }
    public required string EventName { get; init; }
    public string? IpAddress { get; init; }
    public required string Severity { get; init; }    // "Information" | "Warning" | "Error"
    public required IReadOnlyDictionary<string, string?> Fields { get; init; }
}
```

Reads from the Serilog SQL sink table (see Cross-cutting design). Filters by `Properties_UserId = @id`.

---

## Admin-creates-user invitation flow — detailed

This is the largest part of Phase 0. Three moving pieces: a new admin endpoint, a new public-facing endpoint, and a new basic page.

### Step 1 — Admin calls `POST /api/Admin/users`

**Request body** (`AdminCreateUserDto`):
```json
{
  "email": "newuser@example.com",
  "userName": "newuser",
  "firstName": "New",
  "lastName": "User",
  "phoneNumber": "+44...",
  "dateOfBirth": "1990-01-01",
  "country": "GB",
  "addressLine1": "...",
  "addressLine2": "...",
  "addressLine3": "...",
  "city": "...",
  "postcode": "...",
  "roles": ["DefaultUser"],
  "callbackUri": "https://app.example.com/welcome"
}
```

**Validation** (`AdminCreateUserDtoValidator` via FluentValidation):
- `Email` — required, valid email format, not already in use
- `UserName` — required, not already in use, matches existing username regex (alphanumeric + underscore, 3–50 chars — borrow from existing `RegistrationDtoValidator`)
- `FirstName`, `LastName` — required, MaxLength 50
- `PhoneNumber` — optional, valid E.164 if provided
- `DateOfBirth` — optional, must be in the past, age ≥ 13 (mirror existing registration validator)
- Address fields — all optional, MaxLength matches entity
- `Roles` — optional; if provided, each role must exist via `RoleManager.RoleExistsAsync`. **Cannot include `Admin` role** (defence-in-depth — admins are only created via DB seed)
- `CallbackUri` — optional; if provided, must be absolute HTTPS URL on an allowed-host list (reuse existing open-redirect protection helpers)

**Implementation flow** (`AdminService.CreateUserAsync`):
1. Construct `User` entity with all supplied fields. `EmailConfirmed = false`. No password.
2. `await _userService.CreateAsync(user)` — **new no-password overload** (see Implementation files below). Delegates to `UserManager<User>.CreateAsync(user)` (Identity's no-password overload, not currently used anywhere in the codebase).
3. `await _userManager.AddToRolesAsync(user, request.Roles ?? new[] { RolesConstants.DefaultUser })`
4. `var token = await _userManager.GeneratePasswordResetTokenAsync(user)` — Identity's reset-token mechanism (24h TTL by default; see Open questions)
5. Build invitation URI:
   ```csharp
   var invitationUri = QueryHelpers.AddQueryString(
       $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.AcceptInvitation}",
       new Dictionary<string, string?>
       {
           ["email"] = user.Email,
           ["token"] = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token)),
           ["callbackUri"] = request.CallbackUri
       });
   ```
6. Enqueue invitation email:
   ```csharp
   await _emailService.SendEmailAsync(
       user.Email!,
       EmailSubjects.AccountInvitation,
       $"An administrator has created an account for you. To activate your account and set your password, please click the following link: {invitationUri}. This link will expire in 24 hours. If you weren't expecting this invitation, you can safely ignore this email.");
   ```
7. Log `AdminCreatedUser` (5006) with `{AdminUserId}`, `{TargetUserId}`, `{Roles}`, `{IpAddress}`
8. Return `201 Created` with `Location: /api/Admin/users/{id}` and body `ApiResponse<UserSummaryDto>`

**New constants:**
- `EmailSubjects.AccountInvitation = "Account invitation - set your password"`
- `PageRouteConstants.AcceptInvitation = "/AcceptInvitation"`
- `ApiRoutes.AcceptInvitation = "accept-invitation"` (mounted under registration controller)

### Step 2 — User clicks the link, lands on `/AcceptInvitation`

**New Razor Page:** `Pages/AcceptInvitation.cshtml` + `Pages/AcceptInvitation.cshtml.cs`

Mirrors `Pages/ResetPassword.cshtml` exactly in structure. Differences:
- Heading text: "Welcome — set your password to activate your account" (vs "Reset your password")
- Body copy: brief one-liner explaining this completes the invitation
- Form fields: identical (`newPassword`, `confirmPassword`)
- JavaScript submit: POSTs to `/api/registration/accept-invitation` (vs `/api/account/forgotpassword/reset`)
- Success redirect: respects `callbackUri` query param if present; otherwise to `/ActionComplete`

Code-behind reads `email`, `token`, `callbackUri` from query string, exposes them to the view, JavaScript reads them from hidden inputs.

### Step 3 — User submits, hits `POST /api/registration/accept-invitation`

**New endpoint** in `RegistrationController` (it's part of completing initial account setup, not a password operation on an established account).

**Request body** (`AcceptInvitationDto`):
```json
{
  "email": "newuser@example.com",
  "token": "<base64-encoded reset token>",
  "newPassword": "...",
  "callbackUri": "https://app.example.com/welcome"
}
```

**Validation** (`AcceptInvitationDtoValidator`):
- `Email` — required
- `Token` — required
- `NewPassword` — required, matches existing password policy (length, complexity)
- `CallbackUri` — optional; same open-redirect protection as everywhere else

**Implementation flow:**
1. Find user by email. If null → `400 Bad Request` with `"invitation_invalid"` (don't reveal whether the email exists)
2. Check user is in pending-invitation state: `!user.EmailConfirmed && user.PasswordHash == null`. If not → `409 Conflict` `"invitation_already_used"`. This is the only check that prevents an invitation token being used to reset the password of an already-active user.
3. Decode the token, call `await _userManager.ResetPasswordAsync(user, decodedToken, request.NewPassword)`. If failed → return Identity errors in `ApiResponse`.
4. On success: `user.EmailConfirmed = true; await _userManager.UpdateAsync(user)`.
5. Log `InvitationAccepted` (2004) with `{UserId}`, `{IpAddress}`.
6. Return `200 OK` with `ApiResponse<string>` or with a redirect-shape if callback supplied (match existing reset-password behaviour).

**No automatic login.** User is redirected to the callback URI (or `/ActionComplete`) and logs in via the standard flow with the password they just set. Avoids the complexity of issuing a JWT from an unauthenticated endpoint.

### Step 4 — Resend invitation (when 24h expires)

**`POST /api/Admin/users/{id}/resend-invitation`**

Same flow as Step 1, steps 4–8 — but only proceeds if `!user.EmailConfirmed && user.PasswordHash == null`. Generates a fresh reset token, re-sends the email.

**Returns:**
- `200 OK` if resent
- `409 Conflict` `"user_already_active"` if user has already accepted

Emits `AdminResentInvitation` (5007).

---

## Implementation files

### New files

| File | Purpose |
|---|---|
| `Controllers/AdminController.cs` | All `/api/Admin/users/*` endpoints |
| `Services/IAdminService.cs` + `AdminService.cs` | Business logic for admin operations |
| `Shared/Dtos/Response/PagedResponse.cs` | Generic paged envelope |
| `Shared/Dtos/Response/UserSummaryDto.cs` | List endpoint result item |
| `Shared/Dtos/Response/UserDetailDto.cs` | Detail endpoint payload |
| `Shared/Dtos/Response/LockoutInfoDto.cs` | Lockout sub-record |
| `Shared/Dtos/Response/MfaInfoDto.cs` | MFA sub-record |
| `Shared/Dtos/Response/AuditEntryDto.cs` | Audit endpoint result item |
| `Shared/Dtos/AdminCreateUserDto.cs` | Admin-creates-user request body |
| `Shared/Dtos/AcceptInvitationDto.cs` | Invitation acceptance request body |
| `Validation/AdminCreateUserDtoValidator.cs` | FluentValidation rules |
| `Validation/AcceptInvitationDtoValidator.cs` | FluentValidation rules |
| `Pages/AcceptInvitation.cshtml` + `.cs` | Basic invitation-acceptance page |
| New EF migration | Adds `User.CreatedAt` column + Serilog SQL sink table |

### Modified files

| File | Change |
|---|---|
| `Services/IUserService.cs` + `UserService.cs` | Add `CreateAsync(User user)` no-password overload — first use of `UserManager.CreateAsync(user)` in the codebase |
| `Services/IUserService.cs` | (optional) Surface `IsInPendingInvitationState` helper to avoid repeating the `!EmailConfirmed && PasswordHash == null` check |
| `Controllers/RegistrationController.cs` | Add `AcceptInvitationAsync` endpoint |
| `Entities/User.cs` | Add `CreatedAt` property |
| `Storage/DatabaseContext.cs` | Configure `CreatedAt` default value via `HasDefaultValueSql("UTC_TIMESTAMP(6)")` |
| `Constants/EmailSubjects.cs` | Add `AccountInvitation` |
| `Constants/PageRouteConstants.cs` | Add `AcceptInvitation` |
| `Constants/ApiRoutes.cs` | Add `AcceptInvitation` |
| `Constants/SecurityEventIds.cs` | Add 5001–5007 admin events + 2004 invitation event |
| `Extensions/HostExtensions.cs` | Register `IAdminService`, register Serilog SQL sink |
| `appsettings.json` | Add Serilog SQL sink config block |

---

## Tests

### Unit tests

`Tests/AuthenticationService.Tests/Services/AdminServiceTests.cs` and `Tests/AuthenticationService.Tests/Controllers/AdminControllerTests.cs`:

For each endpoint:
- Happy path
- User not found → 404
- Self-target on destructive op → 400 (where applicable)
- Already-in-state idempotency case (lock-already-locked, etc.)
- Wrong role → 403 (one cross-cutting test on the controller is enough; relies on `[Authorize(Policy = AdminOnly)]`)

Plus for invitation flow specifically:
- `CreateUserAsync` — happy path produces user with `EmailConfirmed = false` + no password + invitation email sent
- `CreateUserAsync` — `Admin` role in request → validation failure
- `CreateUserAsync` — duplicate email → validation failure
- `CreateUserAsync` — duplicate username → validation failure
- `AcceptInvitationAsync` — happy path sets password + flips `EmailConfirmed = true`
- `AcceptInvitationAsync` — user already activated → 409
- `AcceptInvitationAsync` — invalid token → 400
- `ResendInvitationAsync` — happy path
- `ResendInvitationAsync` — user already activated → 409

Estimate: ~40 unit tests.

### Integration scenario 11

`AuthenticationService.IntegrationTests/Scenarios/AdminEndpointsTests.cs`:

End-to-end flow:
1. Admin logs in (`admin` / seeded password)
2. Admin POSTs `/api/Admin/users` for a new user
3. Assert: user row in DB has `EmailConfirmed = false`, `PasswordHash = NULL`, correct role assignments
4. Assert: smtp4dev received the invitation email; parse the link
5. New user GETs the invitation link → renders `AcceptInvitation` page
6. New user POSTs `/api/registration/accept-invitation` with a password
7. Assert: user row now has `EmailConfirmed = true`, `PasswordHash != NULL`
8. New user POSTs `/api/Authentication/authenticate` with the new password → 200 + tokens
9. Admin POSTs `/api/Admin/users/{newId}/lock`
10. New user POSTs `/api/Authentication/refresh` → 401
11. Admin POSTs `/api/Admin/users/{newId}/unlock`
12. New user re-authenticates → 200

Covers the full admin-creates-user + lock/unlock lifecycle across replicas.

### Integration scenario 12

Smaller scenario: admin force-password-resets a user, confirms the user's existing sessions die, confirms the reset email arrives and the user can complete the reset.

---

## Open questions

1. **Reset token TTL for invitations.** Identity's default `DataProtectionTokenProviderOptions.TokenLifespan` is 24h. For invitations that's tight — admin creates Friday, user reads Monday. Options:
   - Keep 24h, rely on `resend-invitation` (current plan)
   - Configure a separate token provider with longer TTL just for invitations (more code; cleaner UX)
   - Bump the global default to 72h (affects all reset tokens, including forgot-password — slightly weakens password-reset security)

   **Default: keep 24h + resend.** Operators with a higher cost on "user complaints about expired invites" can revisit.

2. **Force-password-reset email wording.** The user-driven forgot-password email reads "To reset your password, please click..." Should the admin-driven variant clarify that an administrator initiated it? Argument for: transparency. Argument against: same wording reuses the same template / call site / test surface. **Default: same wording — keep the surface tight.** Revisit if users complain about confusing admin-initiated resets.

3. **`UserName` editable via admin?** Not in Phase 0. Username is part of identity — changing it breaks audit trails referencing the old name. If a real need arises (e.g., legal name change request), add `POST /api/Admin/users/{id}/rename` in Phase 0.5 with explicit audit + double-write to a `UserNameHistory` table.

4. **Hard delete vs soft delete?** Phase 0 has neither. Disabling a user = lock them indefinitely. Hard delete would orphan refresh tokens, audit rows, and any external system referencing the user ID — non-trivial. Soft delete (an `IsDeleted` column + filtering) is the right answer when GDPR / right-to-be-forgotten enters scope. Defer.

5. **What happens when admin force-password-resets the seed admin account?** Locks out the operator. Mitigated by self-protection (decision #7) — admin can't reset their own password through this endpoint. Out-of-band recovery (DB seed re-run with new password) is the documented recovery path.

---

## Definition of done

- `AdminController` exposes all 9 endpoints listed in the summary table
- All endpoints gated by `[Authorize(Policy = "AdminOnly")]`
- All destructive endpoints reject self-target with 400
- `PagedResponse<T>` envelope adopted across list endpoints
- Serilog SQL sink configured, audit endpoint queries it
- Invitation flow end-to-end: admin creates user → email lands in inbox → user clicks link → basic page renders → user sets password → user can authenticate
- New `Pages/AcceptInvitation.cshtml` matches the styling of `Pages/ResetPassword.cshtml`
- ~40 unit tests green
- Integration scenarios 11 & 12 green in CI
- README updated with admin endpoint table + invitation flow walk-through
- New security event IDs (5001–5007, 2004) documented in `SecurityEventIds.cs` XMLDoc

---

## Reference materials

- Existing reset-password flow as the structural template:
  - Email send: `AccountController.cs:327–330`
  - URI builder: `AccountHelpers.GenerateResetPasswordUri`
  - Landing page: `Pages/ResetPassword.cshtml`
  - API endpoint: `POST /api/account/forgotpassword/reset`
- Existing email-confirm flow:
  - Send: `RegistrationController.cs:223–246`
  - Landing: `Pages/ActionComplete.cshtml`
- Identity APIs used:
  - `UserManager.CreateAsync(TUser user)` — no-password overload, [docs](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.usermanager-1.createasync)
  - `UserManager.GeneratePasswordResetTokenAsync` + `ResetPasswordAsync` — used for both forgot-password and invitations
