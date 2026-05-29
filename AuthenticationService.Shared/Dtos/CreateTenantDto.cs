using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Body for <c>POST /api/Tenants</c>. PlatformAdmin-only — creates a new tenant.
/// Server validates the name against the tenant-name rules (format, reserved-name list,
/// uniqueness across the platform). <see cref="DisplayName"/> is mutable post-creation;
/// <see cref="Name"/> is not.
/// </summary>
public class CreateTenantDto
{
    /// <summary>
    /// URL-safe, lowercase canonical identifier. Used in API paths and login URL hints.
    /// Immutable once the tenant is created. See <c>TenantConstants.NamePattern</c> for rules.
    /// </summary>
    [Required(ErrorMessage = "Name is required."), MaxLength(50)]
    public string? Name { get; set; }

    /// <summary>
    /// Human-readable label shown in admin UI and emails. Can be changed later.
    /// </summary>
    [Required(ErrorMessage = "DisplayName is required."), MaxLength(255)]
    public string? DisplayName { get; set; }
}
