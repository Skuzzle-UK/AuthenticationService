using AuthenticationService.Enums;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// A customer organisation served by this auth-service deployment. See
/// <c>docs/concepts/multi-tenancy-plan.md</c> for the multi-tenancy design.
/// Users join tenants via <see cref="UserTenantMembership"/>; URLs reference tenants by
/// <see cref="Name"/>; the <see cref="Id"/> GUID is the FK target on tenant-scoped rows.
/// </summary>
public class Tenant
{
    /// <summary>
    /// GUID primary key. Used as the FK target on every tenant-scoped entity.
    /// </summary>
    [Required, MaxLength(36)]
    public string Id { get; set; } = default!;

    /// <summary>
    /// The tenant's canonical short name — URL-safe, lowercase, immutable. Used in
    /// API paths (<c>/api/Tenants/{name}</c>) and login-URL hints
    /// (<c>/login?tenant={name}</c>). Follows the Microsoft / Active Directory
    /// convention where <c>Name</c> is the URL-friendly canonical and
    /// <see cref="DisplayName"/> is the human-facing label. "Renaming" a tenant
    /// changes only <see cref="DisplayName"/>; <see cref="Name"/> is set once at
    /// creation.
    /// </summary>
    [Required, MaxLength(50)]
    public string Name { get; set; } = default!;

    /// <summary>
    /// Human-readable label shown in admin UI / emails. Mutable.
    /// </summary>
    [Required, MaxLength(255)]
    public string DisplayName { get; set; } = default!;

    public TenantStatus Status { get; set; } = TenantStatus.Active;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? SuspendedAt { get; set; }

    [MaxLength(500)]
    public string? SuspensionReason { get; set; }

    /// <summary>
    /// When set, the tenant entered <see cref="TenantStatus.PendingDeletion"/>.
    /// The <c>TenantDeletionSweepService</c> hard-deletes after the retention window.
    /// </summary>
    public DateTimeOffset? PendingDeletionAt { get; set; }

    /// <summary>
    /// Reserved for a future tiered offering (Decision 4) — per-tenant signing keys.
    /// Always null in Phase 1; when populated, JWT issuance uses this key id instead
    /// of the platform default.
    /// </summary>
    [MaxLength(255)]
    public string? DedicatedKeyId { get; set; }

    /// <summary>
    /// Navigation: members of this tenant.
    /// </summary>
    public List<UserTenantMembership> Memberships { get; set; } = [];
}
