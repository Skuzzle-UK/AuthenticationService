using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Body for <c>POST /api/Tenants/{name}/suspend</c>. Suspension is reversible;
/// token issuance for the tenant stops, but existing tokens remain valid until expiry
/// (Decision 6). Reason is recorded in the audit log + on the tenant entity.
/// </summary>
public class SuspendTenantDto
{
    [Required(ErrorMessage = "Reason is required."), MaxLength(500)]
    public string? Reason { get; set; }
}
