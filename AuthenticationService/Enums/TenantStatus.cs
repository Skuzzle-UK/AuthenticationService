namespace AuthenticationService.Enums;

/// <summary>
/// Lifecycle status for a tenant. See <c>docs/concepts/multi-tenancy-plan.md</c>
/// Decision 6 for the rules around each transition.
/// </summary>
public enum TenantStatus
{
    /// <summary>
    /// Normal operation. Token issuance accepted; existing tokens valid.
    /// </summary>
    Active = 0,

    /// <summary>
    /// Token issuance rejected (login fails for users of this tenant). Existing tokens
    /// remain valid until expiry — suspension is deliberately reversible to handle
    /// wrongful-suspend cases without disrupting active sessions. PlatformAdmin can
    /// still manage the tenant; un-suspending restores Active.
    /// </summary>
    Suspended = 1,

    /// <summary>
    /// Tenant is queued for hard-delete. Refresh tokens are cascade-revoked at
    /// status-transition time. The <c>TenantDeletionSweepService</c> background worker
    /// hard-deletes the tenant + all related rows after the retention window expires.
    /// PlatformAdmin can recover from this state until the sweep fires.
    /// </summary>
    PendingDeletion = 2,
}
