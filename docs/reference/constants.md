# Shared constants

Everything in `AuthenticationService.Shared.Constants` is a wire-contract constant — both the auth service and consumer libraries reference the same value. Use these instead of magic strings; renaming the value in one place breaks compilation in both, which is the point.

The `AuthenticationService.Shared` package is referenced transitively by both `AuthenticationService.TokenValidationLib` and `AuthenticationService.TokenClientLib`, so consumers get these for free without an extra reference.

## `ClaimConstants`

JWT claim type names.

| Constant | Value | Notes |
|---|---|---|
| `Sub` | `"sub"` | Subject — the user ID (or `client_id` for service tokens). Stable; use as a foreign key. |
| `Sid` | `"sid"` | Session/refresh-family ID. Persists across rotations within one login session. |
| `Jti` | `"jti"` | Unique per access token. Used by the deny-list and for correlation. |
| `Name` | `"name"` | Display name. Mapped to `User.Identity.Name`. |
| `Email` | `"email"` | Email address. Absent on service tokens. |
| `Role` | `"role"` | Role membership claim. One per role; mapped to `IsInRole`. Absent on service tokens. |
| `Exp` | `"exp"` | Expiration time. Standard JWT. |
| `ClientId` | `"client_id"` | OAuth client ID. Present on service tokens (mirrors `sub`). |
| `Scope` | `"scope"` | Space-separated granted scopes. Present on service tokens. |
| `Azp` | `"azp"` | Authorized party (OIDC core §2). Present on service tokens. |

## `PolicyConstants`

Authorization policy names.

| Constant | Value | Notes |
|---|---|---|
| `AdminOnly` | `"AdminOnly"` | `[Authorize(Policy = PolicyConstants.AdminOnly)]` requires the `Admin` role. |

For scope-based service-to-service policies, use `AddScopePolicy("scope-name")` from `AuthenticationService.TokenValidationLib`. The policy name *is* the scope.

## `RolesConstants`

Identity role names.

| Constant | Value |
|---|---|
| `Admin` | `"Admin"` |
| `DefaultUser` | `"DefaultUser"` |
| `Normalised.Admin` | `"ADMIN"` |
| `Normalised.DefaultUser` | `"DEFAULTUSER"` |

The normalised variants match what `UserManager<User>.GetRolesAsync` returns when queried against the Identity store's normalised role name column. Useful in tests that bypass the manager.

## `AuthSchemeConstants`

`Authorization` header values.

| Constant | Value | Notes |
|---|---|---|
| `Bearer` | `"Bearer"` | The scheme name. |
| `BearerPrefix` | `"Bearer "` | Includes the trailing space — strip this from the start of an `Authorization` header to isolate the token. |

## Auth-service-only constants (not in `Shared`)

These live in `AuthenticationService/Constants/` rather than `AuthenticationService.Shared/Constants/` because they're internal to the auth service and not part of the consumer-side wire contract.

### `SecurityEventIds`

EventId numbers for SIEM-relevant log events. Stable across deploys — SIEM rules match by ID, not by message string. The full table is in [operations/observability.md#siem-contract](../operations/observability.md#siem-contract).

| Range | Category |
|---|---|
| 1000s | Authentication (login, MFA, refresh, logout) |
| 2000s | Registration |
| 3000s | Account management (password, lockout) |
| 4000s | Token state (revocation, replay) |
| 5000s | Admin / s2s (admin actions, client credentials) |

### `RevocationReasons`

Reason strings stamped on `RevokedToken` rows. Driven from controllers / services and surfaced in audit logs.

### `RateLimitPolicies`

Policy names referenced by `[EnableRateLimiting(...)]` attributes. See [concepts/security-model.md#rate-limiting](../concepts/security-model.md#rate-limiting).

### `TokenPurposes`

Identity token-purpose strings (`"reset_password"`, `"email_confirmation"`, etc.) used with the data-protection key ring.

### Other internal constants

`ApiRoutes`, `WellKnownPaths`, `ResponseConstants`, `EmailSubjects`, `ErrorMessages`, `UriConstants`, `UserConstants`, `PageRouteConstants` — all wire constants used internally. Most are pinned by tests in `Tests/AuthenticationService.Tests/Constants/`.

## How they're tested

Every constant class has a pinning test in `Tests/AuthenticationService.Shared.Tests/Constants/ConstantsTests.cs` (for shared ones) or `Tests/AuthenticationService.Tests/Constants/` (for internal ones). The pinning tests assert the literal string value — a change to any value breaks the test loudly, which is the point: these are wire contracts and a silent rename across a release boundary is a bad day.
