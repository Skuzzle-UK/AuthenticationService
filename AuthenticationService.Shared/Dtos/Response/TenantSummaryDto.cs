namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Thin tenant shape returned from <c>GET /api/Tenants</c>. Status is the
/// string name of <c>TenantStatus</c> (Active / Suspended / PendingDeletion) for stable
/// wire compatibility regardless of enum-numeric-value churn.
/// </summary>
public class TenantSummaryDto
{
    public string Id { get; set; } = default!;

    /// <summary>
    /// Canonical short name (URL-friendly). Pairs with <see cref="DisplayName"/>.
    /// </summary>
    public string Name { get; set; } = default!;

    public string DisplayName { get; set; } = default!;
    public string Status { get; set; } = default!;
    public DateTimeOffset CreatedAt { get; set; }
}
