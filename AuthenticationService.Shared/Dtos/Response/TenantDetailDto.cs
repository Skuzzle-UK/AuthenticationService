namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Full tenant detail returned from <c>GET /api/Tenants/{name}</c>. Inherits
/// <see cref="ApiResponse"/> for the standard envelope. Suspension / pending-deletion
/// timestamps are null when not applicable.
/// </summary>
public class TenantDetailDto : ApiResponse
{
    public string Id { get; set; } = default!;

    /// <summary>
    /// Canonical short name (URL-friendly). Pairs with <see cref="DisplayName"/>.
    /// </summary>
    public string Name { get; set; } = default!;

    public string DisplayName { get; set; } = default!;
    public string Status { get; set; } = default!;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? SuspendedAt { get; set; }
    public string? SuspensionReason { get; set; }
    public DateTimeOffset? PendingDeletionAt { get; set; }

    /// <summary>
    /// Count of users currently a member of this tenant (RemovedAt is null).
    /// Useful for "is this tenant safely empty before force-delete?" pre-flight.
    /// </summary>
    public int ActiveMembershipCount { get; set; }
}
