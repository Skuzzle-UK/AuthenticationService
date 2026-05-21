# Validating incoming JWTs (TokenValidationLib)

Your microservice exposes HTTP endpoints. Clients call them with `Authorization: Bearer <jwt>`. This page is how to wire up the validation.

## What you get

Use **`AuthenticationService.TokenValidationLib`** and you get, in two lines:

- **`AddAuthenticationServiceJwt(config)`** — wires JwtBearer against the auth service, configures TokenValidationParameters (ES256-only, issuer/audience pinning, role-claim mapping, the lot).
- **`AddScopePolicy("inventory.read")`** — registers an authorisation policy named after the scope. Apply it with `[Authorize(Policy = "inventory.read")]` and only callers whose JWT carries that scope get through.

No shared secrets. JWKS is fetched once at startup (cached ~24h) and used to verify every token's signature against its `kid` header.

## 1. Add the project / package reference

```xml
<ProjectReference Include="..\AuthenticationService.TokenValidationLib\AuthenticationService.TokenValidationLib.csproj" />
```

(Once published as NuGet, switch to `<PackageReference Include="AuthenticationService.TokenValidationLib" />`.)

`AuthenticationService.Shared` comes in transitively — you get the `ClaimConstants` / `PolicyConstants` / `RolesConstants` constants without an extra reference.

## 2. Configure

```jsonc
// appsettings.json
"AuthenticationService": {
  "Authority": "https://auth.example.com",   // base URL of the auth service
  "Issuer": "https://auth.example.com",      // must match JWTSettings.ValidIssuer in the auth service
  "Audience": "platform-api",
  "RequireHttpsMetadata": true
}
```

> **Why both `Authority` *and* `Issuer`?** They look like the same URL but they're separate concerns:
>
> - `Authority` is the *network URL* JwtBearer contacts to fetch the OIDC discovery doc and signing keys. It's a routing target.
> - `Issuer` is the *logical name* that must appear in every token's `iss` claim, sourced from `JWTSettings.ValidIssuer` in the auth service. It's an identity, not an address.
>
> In production these are usually the same string. In dev they diverge — the auth service advertises `iss: https://auth.example.com` but actually listens on `https://localhost:53217`, so consumers point `Authority` at the localhost URL while keeping `Issuer` as the canonical name.
>
> Setting both explicitly here makes the consumer work in both environments unchanged. If you ever omit `Issuer`, JwtBearer falls back to deriving it from `Authority` — fine in prod where they match, broken in dev where they don't (you'll see `IDX10205: Issuer validation failed`). See [operations/deployment.md §8](../operations/deployment.md#8-https--hostname) for the production guidance.

## 3. Wire it up

```csharp
using AuthenticationService.Shared.Constants;
using AuthenticationService.TokenValidationLib;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthenticationServiceJwt(
    builder.Configuration.GetSection("AuthenticationService"));

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(PolicyConstants.AdminOnly, p => p.RequireRole(RolesConstants.Admin));

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
```

That's it. JwtBearer auto-discovers signing keys from `{Authority}/.well-known/openid-configuration`, caches them in memory, and refreshes periodically.

## 4. Protect endpoints

```csharp
using AuthenticationService.Shared.Constants;

[Authorize]                                               // any authenticated user
[Authorize(Policy = PolicyConstants.AdminOnly)]           // admin only
[Authorize(Roles = RolesConstants.Admin)]                 // role-based, equivalent
public class WidgetsController : ControllerBase { ... }
```

For **scope-based authorisation** (service-to-service callers), use `AddScopePolicy`:

```csharp
builder.Services.AddAuthorizationBuilder()
    .AddScopePolicy("inventory.read")
    .AddScopePolicy("inventory.write");
```

```csharp
[Authorize(Policy = "inventory.read")]
[HttpGet("items/{id}")]
public Task<Item> Get(int id) => ...;
```

Each policy checks the JWT's `scope` claim — a space-separated list per OAuth convention — and returns success iff the requested scope is present. User JWTs (from the `/authenticate` flow) don't carry a `scope` claim and so fail any scope policy by default; this is intentional — scope policies are for service-to-service calls, not user-on-behalf-of calls. See [consumers/outgoing-service-tokens.md](outgoing-service-tokens.md) for the calling side.

## 5. Reading user identity inside endpoints

Standard ASP.NET Core `ClaimsPrincipal`:

```csharp
using AuthenticationService.Shared.Constants;
using System.Security.Claims;

var username = User.Identity?.Name;                          // display name from "name" claim
var isAdmin  = User.IsInRole(RolesConstants.Admin);          // checks "role" claims

var userId   = User.FindFirstValue(ClaimConstants.Sub);      // stable user ID — use this as a foreign key in your DB
var jti      = User.FindFirstValue(ClaimConstants.Jti);      // unique per token; useful for correlation / dedup
var sid      = User.FindFirstValue(ClaimConstants.Sid);      // session/refresh-family ID
var email    = User.FindFirstValue(ClaimConstants.Email);
```

`sub` is the value to persist if you ever need to reference this user from your own data. It never changes; `name` and `email` can. See [consumers/claim-shapes.md](claim-shapes.md) for the full claim contract.

## Available shared constants

From `AuthenticationService.Shared.Constants` (transitively available via the lib reference):

| Class | Members |
|---|---|
| `ClaimConstants` | `Sub`, `Sid`, `Jti`, `Name`, `Email`, `Role`, `Exp`, `ClientId`, `Scope`, `Azp` |
| `PolicyConstants` | `AdminOnly` |
| `RolesConstants` | `Admin`, `DefaultUser` (+ `.Normalised.*`) |
| `AuthSchemeConstants` | `Bearer`, `BearerPrefix` |

Use these instead of magic strings — both sides of the wire stay in sync by construction.

## Common gotchas

- **`Authority` points at the wrong port.** OIDC discovery silently fails, JwtBearer carries on with no signing keys, every request returns 401 with `"The signature key was not found"` even with a valid token. Always verify `Authority` matches the port reported by the auth service's `launchSettings.json`.
- **`RequireHttpsMetadata = true` but the auth service is on HTTP.** Discovery refuses to fetch. Flip to `false` for local dev only.
- **`Issuer` not set, divergent from `Authority` in dev.** `IDX10205: Issuer validation failed`. Always set `Issuer` explicitly per step 2.
- **Token validates but `IsInRole(Admin)` returns false.** The auth service uses `role` (lowercase) as the role claim. The lib sets `RoleClaimType = ClaimConstants.Role` automatically; if you've overridden `TokenValidationParameters` yourself, preserve this.
