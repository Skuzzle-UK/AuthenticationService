# Multi-tenancy plan

> **Status: planning — no code shipped yet.** This document captures the design decisions agreed during the multi-tenancy planning session. All eight foundational decisions are locked; implementation is phased — see [Phasing](#phasing) at the end. Each section locks a specific decision with the trade-off context for future reviewers.

The service today is **single-tenant per deployment**: each platform that adopts this auth service runs its own dedicated instance with one user pool, one client list, one audit trail. Moving to a multi-tenant model lets a single deployment serve multiple customer organisations with isolated user pools, separate audit trails, per-tenant administration, and the option of per-tenant configuration overrides.

We're targeting **logical multi-tenancy** — one database, one process, one signing key, but a `TenantId` column on every tenant-scoped entity with EF query filters enforcing isolation globally. This is the Mode B option from the initial framing; Modes A (deployment-per-tenant), C (database-per-tenant), and D (full service-per-tenant) are out of scope for this plan.

---

## Decision 1 — User ↔ tenant relationship: many-to-many

**Locked**: a user can belong to multiple tenants via a `UserTenantMembership` table.

```
User (1) ─────────── (N) UserTenantMembership (N) ─────────── (1) Tenant
                            └── roles (per membership)
```

Alice has **one** identity (one email, one password, one MFA setup) and joins individual tenants via memberships. Equivalent to Slack / GitHub / Notion / Microsoft Entra guest-user models.

**Rationale**: B2B SaaS where consultants, partners, and cross-org collaborators are realistic personas. The data model anticipates that "Alice the consultant works for both Acme and Globex" is a normal flow, not a future retrofit.

**Implications**:
- `User` table is tenant-independent. Email is globally unique on the platform.
- Password, MFA, SSO links live on `User`. One reset covers all memberships.
- Audit rows reference `(UserId, TenantId)` pairs.
- **Lockout is user-scoped, not membership-scoped.** `IdentityUser.LockoutEnd` and `AccessFailedCount` stay on `AspNetUsers` exactly where Identity put them — the threshold-escalation worker locks the *whole user* across all tenants. Rationale: lockout is a *security* response to malicious activity. The attacker has Alice's credentials or stolen tokens, not "Alice-acting-as-Acme" credentials — locking only the affected tenant leaves the attacker free to pivot into her other memberships using the same stolen material. We use Identity's standard lockout pipeline unchanged; no custom `IUserLockoutStore<User>` needed.
- **Token revocation cascades are user-scoped for security incidents.** When the threshold-escalation worker or the refresh-token-reuse cascade fires, *all* of the user's refresh tokens across every tenant are revoked. Same threat-model reasoning as lockout.
- **Membership removal is tenant-scoped and a separate concept.** A TenantAdmin removing Alice from Acme (she resigned, contract ended) sets `UserTenantMembership.RemovedAt` and cascade-revokes only her *Acme* refresh tokens. Her Globex membership and tokens are untouched — she's still a legitimate user there. This is an *administrative* action, not a security response, and the two operations have separate endpoints with separate audit trails.

---

## Decision 2 — Login flow: credentials + tenant in one request, with URL hint

**Locked**: Model 2d.

```
GET  /login                       ← UI: tenant + email + password fields
GET  /login?tenant=acme           ← same UI but tenant field pre-filled
POST /api/Authentication/authenticate
     body: { tenantName, email, password }
     ← server validates credentials AND validates membership
     ← returns scoped JWT { sub, tid, roles, ... }
```

One login round-trip. The server checks both credentials *and* membership before issuing the token. If credentials are valid but the user isn't a member of the requested tenant, return a generic 401 (don't enumerate tenants for credential stuffers).

**Rationale**: simpler than the "bootstrap then exchange" model (no special audience-restricted bootstrap token). The URL hint gives customer onboarding emails a branded direct-link path (`oursaas.com/login?tenant=acme`) without losing the "I forgot my tenant" recovery path.

**In-app tenant switching** (Phase 2 enhancement): a separate `POST /api/Tenants/switch { tenantName }` endpoint exchanges the current JWT for one with a different `tid`, without re-validating credentials. Slack-style "switch workspace" dropdown.

---

## Decision 3 — Tenant resolution on authenticated requests: JWT `tid` claim alone

**Locked**: clean URLs (`/api/Admin/users`), tenant is read from the JWT's signed `tid` claim. URLs do not carry `/t/{name}/` prefixes.

```
GET  /api/Admin/users
     Authorization: Bearer <JWT with tid: "acme">
     ← TenantResolutionMiddleware reads tid from principal claims,
       populates ITenantAccessor.CurrentTenantId
     ← EF query filters apply WHERE TenantId = "acme" globally
```

**For unauthenticated endpoints that need tenant context** (password reset, email confirmation, MFA links, SSO callbacks): the tenant identifier is **embedded in the data-protected token payload**, not the URL. The payload is already where we put email + purpose; `tid` fits naturally and stays cryptographically bound.

**Rationale**: the JWT signature is the cryptographic boundary; the `tid` claim is what makes the token tenant-bound. Adding `/t/{name}/` URL prefixes adds a second source of truth that has to agree with the JWT (or you get 403s that look like bugs). Industry-standard shape — Auth0, Cognito, Keycloak all do JWT-claim-based tenant resolution.

**Implications**:
- New `TenantResolutionMiddleware` registered **after** JwtBearer (so the principal exists). Populates `ITenantAccessor` (scoped service).
- `DatabaseContext.OnModelCreating` adds a global query filter on every tenant-scoped entity: `e => e.TenantId == _tenantAccessor.CurrentTenantId`.
- Existing protected token formats (password-reset / confirm-email / lockout) extend their payload to carry `tid`. Greenfield deployment (Decision 7) means no in-flight legacy tokens to worry about — every protected token issued post-Phase 3 carries `tid` from day one.

---

## Decision 4 — Signing keys: shared platform key + signed `tid` claim

**Locked**: one ECDSA P-256 keypair signs every JWT issued by this service. JWKS publishes that single key. The `tid` claim is cryptographically bound by the signature, making it the trust boundary.

**Why not per-tenant keys**: equivalent security for the question "can this token act on tenant X?" (the signature covers `tid` either way), but per-tenant keys multiply JWKS document size by tenant count, multiply the key-rotation runbook by tenant count, and force consumer JWKS clients to discover and cache more material. Not the right default for B2B SaaS.

**Forward-compatibility**: the `Tenant` entity gets a nullable `DedicatedKeyId` column reserved for a future tiered offering ("enterprise tier: dedicated signing key"). Phase 1 never sets it; if the business model ever needs per-tenant keys, the schema is ready and the change is local to `EcdsaKeyProvider` + JWT issuance.

---

## Decision 5 — Roles: tenant-scoped roles via memberships, platform-level via Identity roles, dedicated TenantsController

**Locked**:

- **Tenant-scoped roles**: many-to-many between `UserTenantMembership` and the existing ASP.NET Identity `Role` table (which we already inherit from `IdentityRole`). A new `UserTenantMembershipRole` join table holds tenant-scoped role assignments. Alice in Acme can hold `{TenantAdmin, BillingAdmin}` simultaneously. JWT carries `roles: ["TenantAdmin", "BillingAdmin"]` array.
- **Platform-level**: a `PlatformAdmin` role lives in Identity's normal `AspNetRoles` table and is assigned via `AspNetUserRoles` — i.e. through the standard `UserManager.AddToRoleAsync` flow, not via membership. PlatformAdmin holders are not bound to any tenant. The seeded admin user holds this role by default; Phase 4 adds an admin endpoint to assign it to other users.
- **Cross-tenant ops**: dedicated `TenantsController` (route `/api/Tenants`) gated by `[Authorize(Policy = PolicyConstants.PlatformAdminOnly)]`. Bypasses EF global query filters via `IgnoreQueryFilters()`. Every action is audit-logged with `(platformAdminUserId, targetTenantName, action)`.

**Rationale**:
- Multiple roles per membership is composable without exploding the role list ("BillingAdmin + UserAdmin" doesn't need a third combined role).
- A platform-level role (rather than a `bool IsSuperAdmin` column) uses the standard ASP.NET Core authorization pipeline — no special-case claim, no custom policy beyond a one-line `RequireRole`, and platform roles can grow (`PlatformAuditor`, `PlatformBilling`) without schema churn.
- The `AspNetUserRoles` table is the natural home for these — tenant-scoped roles still go through `UserTenantMembershipRole`, so the two scopes are cleanly separated by which join table they live in.
- Dedicated controller for cross-tenant ops gives a clean audit boundary and avoids the impersonation-token complexity (no separate token issuance just for "act as" flows).

**JWT shape**:

```json
// Tenant user with multiple roles in Acme:
{
  "sub": "u-001",
  "tid": "acme",
  "roles": ["TenantAdmin", "BillingAdmin"],
  "aud": "platform-api",
  ...
}

// PlatformAdmin acting platform-wide:
{
  "sub": "u-99",
  "roles": ["PlatformAdmin"],
  "aud": "platform-api",
  ...  // no tid
}
```

Consuming services treat `PlatformAdmin` like any other role on the `roles` claim — no custom claim shape, no custom validation logic. `tid` absence is the signal that the bearer is acting platform-wide.

**Naming note**: `PlatformAdmin` (platform-scoped) is deliberately distinct from `TenantAdmin` (per-tenant scope). They live in different join tables and gate different controllers; reusing the same name would be a footgun given the very different blast radius.

**Role seeding**: platform-level migration seeds:
- `Admin` and `DefaultUser` — pre-multi-tenancy roles, retained for the existing admin endpoints.
- `PlatformAdmin` — new in Phase 1 for the `TenantsController` gate.
- `TenantAdmin` (Phase 4) — full admin rights within a tenant.
- `TenantMember` (Phase 4) — default user role inside a tenant.
- Additional roles (e.g., `BillingAdmin`, `AuditViewer`) added as the product surface grows. Per-tenant custom roles are explicitly **deferred** to a future phase (not part of Phases 1-6; pulled in if and when there's real demand).

---

## Decision 6 — Lifecycle: admin-provisioned + soft-delete with retention + admin force-delete

**Locked**: tenants are created by PlatformAdmins via `POST /api/Tenants`. Self-service tenant creation is deferred to a future product flow.

`Tenant.Status` is an enum:

| Status | Token issuance | Existing tokens | Admin endpoints | Data |
|---|---|---|---|---|
| `Active` | ✅ Normal | ✅ Valid until expiry | ✅ Accessible | Present |
| `Suspended` | ❌ Rejected with "tenant suspended" | Valid until expiry; PlatformAdmin can force-revoke via cascade | ✅ PlatformAdmin only | Present |
| `PendingDeletion` | ❌ Rejected | ❌ Cascade-revoked at status transition | ✅ PlatformAdmin only (to recover) | Present until sweep |
| (hard-deleted) | N/A | N/A | N/A | Removed by sweep |

**Soft-delete** is the default. Calling `DELETE /api/Tenants/{name}` sets status to `PendingDeletion`, stamps `PendingDeletionAt = now`, and cascade-revokes refresh tokens. A new background worker (`TenantDeletionSweepService`, sibling of `DataRetentionCleanupService`) runs every 6 hours, finds tenants with `PendingDeletionAt + retentionDays < now`, and hard-deletes via EF cascade.

**Why suspension doesn't auto-revoke but deletion does**: suspension is deliberately *reversible without disrupting active sessions* — if a tenant is wrongly suspended (billing dispute, support ticket, etc.) we want unsuspending to put things back the way they were. A zero-trust posture that auto-revokes on suspend punishes active users for an administrative state change. Deletion is the opposite: the intent is to wind the tenant down, so revoking sessions at status-transition time aligns the security state with the operational intent. PlatformAdmin can still force-revoke a suspended tenant's tokens via a separate cascade endpoint if a hostile-take-down case ever needs it.

**Force-delete** is the irreversible variant: `POST /api/Tenants/{name}/delete-now` with a confirmation body (e.g., `{ confirmName: "acme" }` — the caller must type the name back to confirm). Cascades immediately.

**`Tenant` entity**:

```csharp
public class Tenant
{
    public string Id { get; set; }                    // GUID (PK)
    public string Name { get; set; }                  // URL-safe, lowercase, unique — e.g. "acme"
    public string DisplayName { get; set; }           // "Acme Corporation"
    public TenantStatus Status { get; set; }          // Active | Suspended | PendingDeletion
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? SuspendedAt { get; set; }
    public string? SuspensionReason { get; set; }
    public DateTimeOffset? PendingDeletionAt { get; set; }
    public string? DedicatedKeyId { get; set; }       // Decision 4: reserved, null in v1
}
```

**Naming convention**: we follow the Microsoft / Active Directory shape — `Name` is the URL-safe canonical short identifier (`"acme"`) and `DisplayName` is the human-facing label (`"Acme Corporation"`). "Renaming" a tenant changes only `DisplayName`; `Name` is set once at creation and is immutable thereafter. We considered `Slug` (too slangy for a public data model), `Alias` (misleading — it's the primary name, not an alternative), and `Handle` / `Identifier` (less recognised by integrators).

**Name validator**: lowercase, regex `^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$` (must start and end with alphanumeric, hyphens allowed in the middle, 3-50 chars total). Additional rules: reject consecutive hyphens (`--`), reject pure-numeric names (`123`), reject reserved names (`admin`, `api`, `www`, `t`, `oauth`, `account`, `login`, `signup`, plus any other path segments the auth service uses). The reserved list is a `DatabaseProviders.cs`-style constants file.

**URL vs Id convention**: URLs reference tenants by `Name` for human readability (`/api/Tenants/acme`). The `Id` GUID is only used internally as the FK target on tenant-scoped entities. The `Name` is immutable once a tenant is created — renaming a tenant changes only `DisplayName`, never `Name`.

---

## Decision 7 — Migration strategy: greenfield, no backfill

**Locked**: no existing production data needs preserving. All current deployments are pre-prod / development DBs that can be dropped and recreated cleanly.

This collapses Phase 2's migration story significantly:

- **`TenantId` columns** are added as `NOT NULL` from the start, with no default and no backfill step.
- **Lockout state stays on `User`** (user-scoped, per Decision 1's revised model). No column moves, no custom `IUserLockoutStore<User>` implementation, no call-site updates. Identity's standard lockout pipeline works unchanged — the threshold-escalation worker locks the whole user, affecting all their memberships simultaneously.
- **Composite unique constraints** drop the old single-column versions and replace them — empty tables means no duplicate-value cleanup required.
- **No `legacy` default tenant.** The first tenant in any deployment is whatever the operator creates via the `TenantsController` endpoint after their initial admin login.
- **Single EF migration per provider** captures the whole Phase 2 shape — no need for the multi-step pattern (add nullable → backfill → set not-null → drop old constraint).

**Developer workflow**: when pulling these changes into a local dev DB, drop and recreate:

```bash
dotnet ef database drop --project AuthenticationService.Migrations.MySql --startup-project AuthenticationService.Migrations.MySql
dotnet ef database update --project AuthenticationService.Migrations.MySql --startup-project AuthenticationService.Migrations.MySql
```

(Same shape for SqlServer and Postgres against their respective migrations projects.)

**Future-deployed services**: when a real production deployment lands later, this is a clean migration with no schema migration drama — the service comes up with empty tenant tables and the operator's first action is to create their tenant via the admin reset flow + `TenantsController` endpoint sequence.

---

## Decision 8 — Per-tenant configuration overrides: JSON column on `Tenant`, Phase 6

**Locked storage shape**: a single `ConfigJson` column on the `Tenant` entity, EF-mapped to a strongly-typed `TenantConfig` record. Tenant value if set, otherwise platform default.

```csharp
public class Tenant
{
    // ... other columns ...
    public TenantConfig? Config { get; set; }   // EF maps to ConfigJson column
}

public record TenantConfig
{
    public PasswordPolicyOverrides? Password { get; init; }
    public LockoutPolicyOverrides? Lockout { get; init; }
    public MfaPolicyOverrides? Mfa { get; init; }
    public EmailBrandingOverrides? EmailBranding { get; init; }
    public RateLimitOverrides? RateLimits { get; init; }
    public TokenLifetimeOverrides? Tokens { get; init; }
}
```

Each override record is a nullable-fields-only shape: any field left null means "use platform default for this specific setting." The resolution layer (an `ITenantPolicyResolver` service) merges per-setting:

```csharp
var length = tenant.Config?.Password?.RequiredLength ?? platform.Password.RequiredLength;
```

**Why JSON column** over alternatives:
- **Typed via EF Core 10's native JSON column mapping** on all three providers (Postgres `jsonb`, SqlServer `nvarchar(max)` + json functions, MySQL `JSON`). Strongly-typed deserialisation; no string-bag awkwardness. *Caveat*: Oracle's `MySql.EntityFrameworkCore` provider has historically had weaker JSON support than Pomelo — Phase 6 may discover we need a `ValueConverter<TenantConfig, string>` helper specifically on the MySQL branch. Verify the round-trip in the Phase 6 quirks suite; the contingency cost is small.
- **No new migration per added setting** — extending `TenantConfig` is a code change, not a schema change. The setting starts returning null for existing tenants until they configure it (which is exactly the desired "platform default" behaviour).
- **Single source of truth per tenant** — one row to fetch, no join fan-out across N override tables.
- **Avoids the wide-table problem** — `Tenant` doesn't accumulate dozens of nullable columns over time.

**What goes in `TenantConfig` (Phase 6 scope, in rough order of demand)**:

| Override | Field | Notes |
|---|---|---|
| Password policy | `RequiredLength`, `RequireDigit`, `RequireUppercase`, `RequireLowercase`, `RequireNonAlphanumeric`, `RequiredUniqueChars` | Most-requested for compliance / industry-specific rules. Lower bounds enforced by validator (e.g., `RequiredLength >= 8` regardless of override). |
| Lockout policy | `MaxFailedAccessAttempts`, `DefaultLockoutDurationInMinutes` | Per-tenant aggressiveness of *the policy*, not the lockout state. Per Decision 1, the lockout state itself is user-scoped on `AspNetUsers` — when a login attempt fails at Acme's login, the resolver looks up Acme's threshold (e.g., 3 attempts) and the user's *global* `AccessFailedCount` is checked against it. Once the lock fires, the user is locked everywhere. Different tenants can have different thresholds (Acme=3, Globex=10), and whichever tenant the user authenticates against contributes its threshold to the check. |
| MFA policy | `MfaRequired` (`Disabled` / `Optional` / `Required`), allowed providers | High-demand — enterprise customers usually want this from day one. |
| Email branding | `FromAddress`, `FromName`, `LogoUrl`, `SignatureFooter` | SPF/DKIM caveats on `FromAddress` — operator may need to configure the SMTP relay to accept the tenant's domain. |
| Rate-limit quotas | per-tenant ceiling (overlays global per-IP / per-user limits) | Fairness; rarely customer-facing, more operator-facing. |
| Token lifetimes | `AccessTokenExpiryInMinutes`, `RefreshTokenExpiryInDays` | Useful for kiosk-style deployments; bounds enforced (e.g., max 60 minutes for access tokens). |

**What stays platform-global** (not in `TenantConfig`):
- JWT algorithm (`ES256`)
- Data-protection key ring config
- DB / Redis connection strings
- Telemetry / OTLP endpoint
- HTTPS enforcement
- The signing key itself (until / unless Decision 4's tiered future ships)

**Why SSO config is NOT in `TenantConfig`**: SSO provider configuration carries secrets (client secrets) that should be at-rest encrypted differently from the rest of `TenantConfig`, and it's typically read on every login (so it benefits from being its own indexed table). SSO config gets a dedicated `TenantSsoProvider` entity in Phase 5, separate from this generic config blob.

**Validation**: per-setting lower bounds + reasonable upper bounds enforced by a `TenantConfigValidator` service. Tenants can't set password length to 4, or access-token TTL to 30 days — the validator clamps or rejects. Bounds live in code alongside the platform defaults so they evolve together.

**Audit**: every change to `Tenant.Config` writes a `SecurityEvent` with a `before` and `after` diff. Per-tenant config changes are security-relevant and need a tamper-evident trail.

---

## JWT shape summary

```json
// Tenant user (most common):
{
  "iss": "https://auth.example.com",
  "sub": "u-001",
  "tid": "acme",
  "roles": ["TenantAdmin"],
  "aud": "platform-api",
  "exp": ...,
  "jti": "..."
}

// PlatformAdmin acting platform-wide (no tid):
{
  "iss": "https://auth.example.com",
  "sub": "u-99",
  "roles": ["PlatformAdmin"],
  "aud": "platform-api",
  ...
}

// PlatformAdmin acting on a specific tenant (audited):
{
  "iss": "https://auth.example.com",
  "sub": "u-99",
  "tid": "acme",
  "roles": ["PlatformAdmin"],
  "audit_acting_as_platform": true,
  ...
}
```

Consuming services (`TokenValidationLib`):
- Today's `[Authorize(Roles = ...)]` continues to work — Identity's role-claim mapping reads `roles` (array) naturally. `[Authorize(Roles = "PlatformAdmin")]` is the gate for platform-wide endpoints.
- New helper: `HttpContext.User.GetTenantId()` extension in `TokenValidationLib` so consumers can apply their own per-tenant authorization easily. `IsInRole("PlatformAdmin")` covers the platform check — no separate helper.

---

## Data model summary

**Tenant-scoped entities** (gain `TenantId` column + composite unique constraints + EF query filter):

- `RefreshToken` (composite: `(TenantId, TokenHash)` unique)
- `RevokedToken` (composite: `(TenantId, TokenJti)` unique)
- `RevokedTokenAccessAttempt`
- `SecurityEvent`
- `Client` (composite: `(TenantId, Id)` unique — i.e., the OAuth `client_id` is unique per tenant, not globally)
- `ClientScope` (composite: `(TenantId, ClientId, Audience, Scope)` unique)

**Tenant-independent entities** (no `TenantId` column):

- `User` (identity is platform-wide)
- `Role` (platform-defined; per-tenant custom roles deferred)
- `Tenant` itself (the root)

**New entities**:

- `Tenant` (per Decision 6).
- `UserTenantMembership` — `(Id, UserId, TenantId, CreatedAt, RemovedAt, RemovedReason, ...)`. Per-tenant membership state — when Alice was added to this tenant, when (if) she was removed by an admin, and why. No lockout state lives here — lockout is user-scoped on `AspNetUsers` (per Decision 1). The login pipeline rejects tokens for memberships where `RemovedAt is not null`.
- `UserTenantMembershipRole` — join table for many-to-many roles per membership.

---

## Phasing

Each phase ships independently and leaves the codebase in a working state.

### Phase 1 — Foundation (~2 days)
- `Tenant` entity, `Status` enum, name validator.
- `UserTenantMembership` entity, `UserTenantMembershipRole` join.
- `ITenantAccessor` service.
- `TenantResolutionMiddleware` reading `tid` claim.
- `PlatformAdmin` role seeded + assigned to the seeded admin user via `AspNetUserRoles`.
- `TenantsController` endpoints (route `/api/Tenants`) to create / suspend / list tenants, gated by `[Authorize(Policy = PlatformAdminOnly)]`.
- Migrations × 3 providers (Tenants + Memberships tables only — no `TenantId` on other entities yet).
- Unit tests for tenant validation + lifecycle.

### Phase 2 — Data model + EF filters (~2 days)
- `TenantId NOT NULL` columns on all scoped entities (no backfill — Decision 7).
- EF global query filters using `ITenantAccessor`.
- Composite unique constraint migrations (drop old, add new).
- Lockout state stays on `User` (user-scoped per Decision 1; Identity's pipeline works unchanged).
- Login pipeline updated to reject tokens for memberships where `RemovedAt is not null` (membership-state check is *separate from* lockout).
- Single EF migration per provider (× 3 — MySql, SqlServer, Postgres).
- Existing scenario tests updated to seed via the new tenant/membership flow and pass.

### Phase 3 — Auth flow (~3 days)
- Tenant-aware login (Model 2d: credentials + `tenantName`).
- `tid` + `roles` claims on every issued JWT.
- Tenant-aware refresh / revoke / logout flows.
- **Two cascade variants** for refresh-token revocation:
  - `RevokeAllRefreshTokensForUserAsync(userId)` — user-scoped, used by the threshold-escalation worker and the reuse-detection cascade (security incidents — Decision 1).
  - `RevokeAllRefreshTokensForUserInTenantAsync(userId, tenantId)` — tenant-scoped, used when a TenantAdmin removes a user from their tenant (administrative action).
- Data-protected tokens (password reset, email confirm, MFA, lockout) carry `tid` in payload.
- `TokenValidationLib` exposes a `GetTenantId()` extension. Platform-admin checks use the standard `IsInRole("PlatformAdmin")` — no helper needed.
- Integration tests for tenant isolation (cross-tenant access blocked at every layer) *plus* security tests asserting that a security cascade locks across all of a user's memberships, not just the affected tenant.

### Phase 4 — Admin + PlatformAdmin model (~2 days)
- `TenantsController` evolves with cross-tenant inspection helpers (search users across tenants, etc.). Core CRUD already exists from Phase 1.
- Admin endpoints for assigning / revoking the `PlatformAdmin` role.
- TenantAdmin role assignment endpoints (per-tenant via `UserTenantMembershipRole`).
- Multi-role membership UI / admin endpoints.

### Phase 5 — SSO per tenant (~3 days)
- Each tenant configures its own SSO providers via the `TenantSsoProvider` entity (per Decision 8) — one row per configured provider, with `(TenantId, ProviderType)` as the natural key. Client secrets at-rest-encrypted via the existing data-protection pipeline.
- Tenant-aware OIDC / OAuth callback handlers.
- Google + Microsoft + GitHub as the initial provider set.
- Login UI: per-tenant "Sign in with..." buttons reflect the tenant's configured providers.

### Phase 6 — Per-tenant config overrides (~3-4 days)
- `Tenant.ConfigJson` column added via migration (× 3 providers).
- `TenantConfig` record + nested override records (`PasswordPolicyOverrides`, `LockoutPolicyOverrides`, `MfaPolicyOverrides`, `EmailBrandingOverrides`, `RateLimitOverrides`, `TokenLifetimeOverrides`).
- `ITenantPolicyResolver` service: per-setting "tenant value if set, otherwise platform default" merge.
- Existing policy-aware services (password validator, lockout cascade, MFA gate, etc.) routed through the resolver instead of reading `IOptions` directly.
- `TenantConfigValidator` enforcing lower/upper bounds per setting.
- TenantAdmin endpoints for getting / updating the tenant's config; PlatformAdmin can view any tenant's config.
- Every config change writes a `SecurityEvent` with before/after diff for audit.
- Tests across all three providers verifying JSON column round-trip + override resolution.

**Total estimate**: ~12-13 days of focused work for Phases 1-5; Phase 6 (~3-4 days) is naturally a separate effort. The "user-scoped lockout" decision saved a half-day-to-day of custom Identity-store work that the earlier version of this plan had on the critical path.

---

## What this does NOT include

- Per-tenant **physical** isolation (Mode C — database per tenant). Out of scope.
- Per-tenant signing keys (Decision 4 deferred future).
- Self-service tenant creation (Decision 6 deferred).
- Per-tenant custom roles (Decision 5 deferred — system roles only in v1).
- Cross-tenant analytics or reporting endpoints.
- Tenant migration (moving a user's data from Tenant A to Tenant B).

These are all reasonable future extensions but not required for a viable B2B SaaS multi-tenancy baseline.

---

## See also

- [TODO.md](../../TODO.md) — phase-by-phase status as work lands.
- [docs/architecture.md](../architecture.md) — how the multi-tenancy plumbing fits into the overall service.
- [docs/concepts/security-model.md](security-model.md) — the existing security stance; multi-tenancy preserves it.
