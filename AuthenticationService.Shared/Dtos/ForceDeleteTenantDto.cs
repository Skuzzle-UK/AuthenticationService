using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Body for <c>POST /api/Tenants/{name}/delete-now</c>. Force-delete is
/// irreversible — bypasses the soft-delete retention window. Caller must type the
/// tenant name back in <see cref="ConfirmName"/> to prove intent (Decision 6's
/// "delete-now confirmation").
/// </summary>
public class ForceDeleteTenantDto
{
    /// <summary>
    /// Must exactly match the tenant name being deleted. Server rejects if it doesn't —
    /// stops accidental deletion via copy-pasted curls etc.
    /// </summary>
    [Required(ErrorMessage = "ConfirmName is required."), MaxLength(50)]
    public string? ConfirmName { get; set; }
}
