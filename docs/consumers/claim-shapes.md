# Claim shapes

Two kinds of token are issued by this auth service: **user tokens** (someone signed in via `/authenticate`) and **service tokens** (a machine signed in via `/oauth/token` client-credentials). Both are signed by the same auth service, validate via the same JWKS, and use the same JwtBearer pipeline on the consumer side. The difference is in the claims.

## User token

Issued when an end-user authenticates with email + password (and MFA, if enabled).

| Claim | Source | Notes |
|---|---|---|
| `sub` | `User.Id` (GUID) | **Stable user ID.** Use this as a foreign key in consumer databases — `name` and `email` can change. |
| `sid` | `RefreshToken.FamilyId` | Session/refresh-family ID. Persists across rotations within one login session. Used internally for per-device logout. |
| `jti` | New GUID per token | Unique per access token. Used by the deny-list and for correlation. |
| `name` | `User.UserName` | Display name. Mapped to `User.Identity.Name` for `ClaimsPrincipal`. |
| `email` | `User.Email` | Email address. |
| `role` | (multi-value) | One claim per role assignment. Mapped to `ClaimsPrincipal.IsInRole`. |
| `iss` | `JWTSettings.ValidIssuer` | Validated by JwtBearer. |
| `aud` | `JWTSettings.ValidAudience` | Validated by JwtBearer. |
| `exp` | issue time + `JWTSettings.ExpiryInMinutes` | Default 5 minutes. |

## Service token

Issued via `POST /oauth/token` with the client-credentials grant.

| Claim | Value | Notes |
|---|---|---|
| `iss` | `JWTSettings.ValidIssuer` | Same as user JWTs — same JWKS validates both. |
| `aud` | The requested audience (e.g. `inventory-api`) | Per-service. Consumers configure `ValidAudience` to match. |
| `sub` | The `client_id` | **NOT a user ID.** Consumers can distinguish by sub shape. |
| `client_id` | Mirrors `sub` | Explicit. Some tools (Postman, Insomnia) prefer this. |
| `scope` | Space-separated granted scopes | OAuth standard. Consumers parse and check via `AddScopePolicy`. |
| `iat` | Issued-at timestamp | Standard. |
| `exp` | `iat + ClientCredentialsSettings.TokenLifetime` | Default 12 hours. |
| `jti` | New `Guid.NewGuid()` | Standard. |
| `azp` | `client_id` | Authorized party (OIDC core, §2). |

**Deliberately absent:** `email`, `name`, `role`, `sid`, `nbf`. User-token-specific claims must NOT be on service tokens — consumers can write `if (User.HasClaim("email", ...))` to distinguish.

## Distinguishing the two in a downstream

Both kinds validate identically. The consumer side gets the claim soup; pick which kind you're dealing with by *absence* of user-only claims:

```csharp
if (User.HasClaim(c => c.Type == ClaimConstants.Email))
{
    // User token — a real human is making the call (possibly via a chain of services
    // that forwarded the JWT). User.Identity.Name, IsInRole, etc. are all populated.
}
else if (User.HasClaim(c => c.Type == ClaimConstants.ClientId))
{
    // Service token — a service identity is calling under client-credentials.
    // Sub is the client_id, not a user id. Use scope-based policies to gate.
    var callerClient = User.FindFirstValue(ClaimConstants.Sub);
    var scopes = User.FindFirstValue(ClaimConstants.Scope)?.Split(' ') ?? [];
}
```

## Gating endpoints by kind

For machine-only endpoints, use scope-based policies. User tokens don't carry `scope`, so any scope policy filters them out by default:

```csharp
[Authorize(Policy = "inventory.read")]              // → service tokens only (they have the scope)
[HttpGet("items/{id}")]
public Task<Item> Get(int id) => ...;
```

For user-only endpoints, role policies or just `[Authorize]` will work — service tokens carry no roles:

```csharp
[Authorize(Roles = "Admin")]                        // → user tokens only (with Admin role)
[HttpPost("admin/promote")]
public IActionResult Promote(...) => ...;
```

If you need to be explicit ("I want a user token, period") you can also check for `User.HasClaim(c => c.Type == ClaimConstants.Sub && c.Value != User.FindFirstValue(ClaimConstants.ClientId))` — but in practice the scope/role discriminator is sufficient.

## See also

- [consumers/validating-incoming-tokens.md](validating-incoming-tokens.md) — wiring + scope policy registration
- [consumers/outgoing-service-tokens.md](outgoing-service-tokens.md) — minting service tokens
- [concepts/service-to-service.md](../concepts/service-to-service.md) — the design rationale
