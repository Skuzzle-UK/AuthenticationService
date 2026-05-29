namespace AuthenticationService.Services;

/// <summary>
/// Scoped accessor for the current request's tenant. Populated by
/// <c>TenantResolutionMiddleware</c> after JwtBearer authentication has built the
/// principal. Null when the request isn't tenant-bound (e.g., login endpoint before
/// authentication completes, platform-admin endpoints acting platform-wide).
///
/// Phase 1: read-only consumers exist (entity scaffolding); the EF global query
/// filters that consume <see cref="CurrentTenantId"/> arrive in Phase 2.
///
/// Platform-level authorization (the <c>PlatformAdmin</c> role) is enforced by the
/// standard <c>[Authorize(Roles = ...)]</c> pipeline, not via this accessor — keeping
/// the accessor focused on tenant identity only.
/// </summary>
public interface ITenantAccessor
{
    /// <summary>
    /// Tenant id (GUID string) for the current request, or null if not tenant-bound.
    /// </summary>
    string? CurrentTenantId { get; }

    /// <summary>
    /// Tenant name (URL-safe canonical) for the current request, or null. Convenience
    /// for logging / SecurityEvent enrichment — the canonical FK target is
    /// <see cref="CurrentTenantId"/>.
    /// </summary>
    string? CurrentTenantName { get; }

    /// <summary>
    /// Set by middleware once the principal is built. Idempotent within a request.
    /// </summary>
    void SetTenantContext(string? tenantId, string? tenantName);
}

internal sealed class TenantAccessor : ITenantAccessor
{
    public string? CurrentTenantId { get; private set; }
    public string? CurrentTenantName { get; private set; }

    public void SetTenantContext(string? tenantId, string? tenantName)
    {
        CurrentTenantId = tenantId;
        CurrentTenantName = tenantName;
    }
}
