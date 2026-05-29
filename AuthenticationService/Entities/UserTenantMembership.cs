using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// A user's membership in a tenant. Per Decision 1 in the multi-tenancy plan,
/// users belong to many tenants; this row is the join. Lockout state is NOT here —
/// it stays user-scoped on <see cref="User"/> as Identity intended (Decision 1's
/// security rationale: an attacker with stolen credentials can pivot between tenants,
/// so lockout must be global, not per-tenant). What lives here is membership
/// lifecycle: when the user joined, whether/when an admin removed them, and why.
/// </summary>
public class UserTenantMembership
{
    /// <summary>
    /// GUID primary key.
    /// </summary>
    [Required, MaxLength(36)]
    public string Id { get; set; } = default!;

    [Required]
    public string UserId { get; set; } = default!;

    public User User { get; set; } = default!;

    [Required, MaxLength(36)]
    public string TenantId { get; set; } = default!;

    public Tenant Tenant { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Set when a TenantAdmin removes this user from the tenant. Login pipeline
    /// rejects tokens for memberships where this is non-null. Soft-delete by design —
    /// audit + restore-ability beat hard-delete here.
    /// </summary>
    public DateTimeOffset? RemovedAt { get; set; }

    [MaxLength(500)]
    public string? RemovedReason { get; set; }

    /// <summary>
    /// Navigation: roles this member holds within this tenant. Many-to-many via the
    /// <see cref="UserTenantMembershipRole"/> join (per Decision 5: multi-role
    /// composition without exploding the role list).
    /// </summary>
    public List<UserTenantMembershipRole> RoleAssignments { get; set; } = [];
}
