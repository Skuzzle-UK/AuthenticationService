using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// Join table for the many-to-many between <see cref="UserTenantMembership"/> and the
/// existing ASP.NET Identity <see cref="Role"/> table. Replaces the use of Identity's
/// <c>AspNetUserRoles</c> for tenant-scoped role assignments (per Decision 5).
/// </summary>
public class UserTenantMembershipRole
{
    [Required, MaxLength(36)]
    public string MembershipId { get; set; } = default!;

    public UserTenantMembership Membership { get; set; } = default!;

    [Required]
    public string RoleId { get; set; } = default!;

    public Role Role { get; set; } = default!;

    public DateTimeOffset AssignedAt { get; set; } = DateTimeOffset.UtcNow;
}
