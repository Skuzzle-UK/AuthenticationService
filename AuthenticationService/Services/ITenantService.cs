using AuthenticationService.Shared.Dtos.Response;

namespace AuthenticationService.Services;

/// <summary>
/// Business logic behind <c>TenantsController</c> for tenant lifecycle. All operations
/// log a <c>SecurityEvent</c> tagged with the caller's user id for audit. The caller is
/// guaranteed to hold <c>PlatformAdmin</c> by the controller-level <c>[Authorize]</c>
/// gate; the role isn't a parameter on these methods because the service doesn't need
/// to re-verify it.
/// </summary>
public interface ITenantService
{
    /// <summary>
    /// Creates a new tenant. <paramref name="name"/> is validated, lower-cased, and
    /// checked against the existing platform set. Created tenants start in
    /// <c>Active</c> status.
    /// </summary>
    Task<CreateTenantResult> CreateAsync(string name, string displayName, string callerUserId, CancellationToken ct);

    Task<IReadOnlyList<TenantSummaryDto>> ListAsync(CancellationToken ct);

    /// <summary>
    /// Returns null when no tenant with that name exists. Membership count is computed
    /// against the active memberships (RemovedAt is null) — useful for the
    /// "tenant safe to force-delete?" pre-flight.
    /// </summary>
    Task<TenantDetailDto?> GetByNameAsync(string name, CancellationToken ct);

    /// <summary>
    /// Transitions Active → Suspended. Reason recorded on the entity + SecurityEvent.
    /// Already-suspended tenants return <c>InvalidStateTransition</c>.
    /// </summary>
    Task<TenantLifecycleResult> SuspendAsync(string name, string reason, string callerUserId, CancellationToken ct);

    /// <summary>
    /// Transitions Suspended → Active. Active tenants return <c>InvalidStateTransition</c>.
    /// </summary>
    Task<TenantLifecycleResult> UnsuspendAsync(string name, string callerUserId, CancellationToken ct);

    /// <summary>
    /// Soft-delete: transitions to PendingDeletion. The <c>TenantDeletionSweepService</c>
    /// hard-deletes after the retention window. Reversible until the sweep fires.
    /// </summary>
    Task<TenantLifecycleResult> SoftDeleteAsync(string name, string callerUserId, CancellationToken ct);

    /// <summary>
    /// Hard-delete with confirmation. Caller must type the name back in
    /// <paramref name="confirmName"/>; mismatch returns <c>ConfirmationMismatch</c>.
    /// Cascades through every tenant-scoped row.
    /// </summary>
    Task<TenantLifecycleResult> ForceDeleteAsync(string name, string confirmName, string callerUserId, CancellationToken ct);
}
