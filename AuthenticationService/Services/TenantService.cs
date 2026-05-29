using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Storage;
using AuthenticationService.Validators;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Services;

/// <summary>
/// Tenant lifecycle implementation. All mutating ops write a <see cref="SecurityEvent"/>
/// (via Serilog → <c>SecurityEventSink</c>) for audit. State-transition rules per
/// Decision 6 of the multi-tenancy plan.
/// </summary>
public class TenantService : ITenantService
{
    private readonly DatabaseContext _db;
    private readonly ITenantNameValidator _nameValidator;
    private readonly ILogger<TenantService> _logger;

    public TenantService(
        DatabaseContext db,
        ITenantNameValidator nameValidator,
        ILogger<TenantService> logger)
    {
        _db = db;
        _nameValidator = nameValidator;
        _logger = logger;
    }

    public async Task<CreateTenantResult> CreateAsync(
        string name,
        string displayName,
        string callerUserId,
        CancellationToken ct)
    {
        var normalised = name.Trim().ToLowerInvariant();

        if (_nameValidator.Validate(normalised) is { } reason)
        {
            return new CreateTenantResult.InvalidName(reason);
        }

        // AnyAsync rather than First — we don't need the row, just the existence check.
        if (await _db.Tenants.AnyAsync(t => t.Name == normalised, ct))
        {
            return new CreateTenantResult.NameAlreadyExists();
        }

        var tenant = new Tenant
        {
            Id = Guid.NewGuid().ToString(),
            Name = normalised,
            DisplayName = displayName.Trim(),
            Status = TenantStatus.Active,
        };

        _db.Tenants.Add(tenant);
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation(
            SecurityEventIds.TenantCreated,
            "Tenant {TenantName} created by PlatformAdmin {CallerUserId}",
            tenant.Name, callerUserId);

        return new CreateTenantResult.Success(tenant.Id, tenant.Name);
    }

    public async Task<IReadOnlyList<TenantSummaryDto>> ListAsync(CancellationToken ct)
    {
        return await _db.Tenants
            .AsNoTracking()
            .OrderBy(t => t.Name)
            .Select(t => new TenantSummaryDto
            {
                Id = t.Id,
                Name = t.Name,
                DisplayName = t.DisplayName,
                Status = t.Status.ToString(),
                CreatedAt = t.CreatedAt,
            })
            .ToListAsync(ct);
    }

    public async Task<TenantDetailDto?> GetByNameAsync(string name, CancellationToken ct)
    {
        var normalised = name.Trim().ToLowerInvariant();

        var tenant = await _db.Tenants
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.Name == normalised, ct);

        if (tenant is null)
        {
            return null;
        }

        var activeMembershipCount = await _db.UserTenantMemberships
            .AsNoTracking()
            .CountAsync(m => m.TenantId == tenant.Id && m.RemovedAt == null, ct);

        return new TenantDetailDto
        {
            Id = tenant.Id,
            Name = tenant.Name,
            DisplayName = tenant.DisplayName,
            Status = tenant.Status.ToString(),
            CreatedAt = tenant.CreatedAt,
            SuspendedAt = tenant.SuspendedAt,
            SuspensionReason = tenant.SuspensionReason,
            PendingDeletionAt = tenant.PendingDeletionAt,
            ActiveMembershipCount = activeMembershipCount,
        };
    }

    public async Task<TenantLifecycleResult> SuspendAsync(
        string name,
        string reason,
        string callerUserId,
        CancellationToken ct)
    {
        var tenant = await FindByNameAsync(name, ct);
        if (tenant is null) return new TenantLifecycleResult.NotFound();

        if (tenant.Status != TenantStatus.Active)
        {
            return new TenantLifecycleResult.InvalidStateTransition(tenant.Status.ToString());
        }

        tenant.Status = TenantStatus.Suspended;
        tenant.SuspendedAt = DateTimeOffset.UtcNow;
        tenant.SuspensionReason = reason.Trim();
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation(
            SecurityEventIds.TenantSuspended,
            "Tenant {TenantName} suspended by PlatformAdmin {CallerUserId}: {Reason}",
            tenant.Name, callerUserId, reason);

        return new TenantLifecycleResult.Success();
    }

    public async Task<TenantLifecycleResult> UnsuspendAsync(
        string name,
        string callerUserId,
        CancellationToken ct)
    {
        var tenant = await FindByNameAsync(name, ct);
        if (tenant is null) return new TenantLifecycleResult.NotFound();

        if (tenant.Status != TenantStatus.Suspended)
        {
            return new TenantLifecycleResult.InvalidStateTransition(tenant.Status.ToString());
        }

        tenant.Status = TenantStatus.Active;
        tenant.SuspendedAt = null;
        tenant.SuspensionReason = null;
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation(
            SecurityEventIds.TenantUnsuspended,
            "Tenant {TenantName} unsuspended by PlatformAdmin {CallerUserId}",
            tenant.Name, callerUserId);

        return new TenantLifecycleResult.Success();
    }

    public async Task<TenantLifecycleResult> SoftDeleteAsync(
        string name,
        string callerUserId,
        CancellationToken ct)
    {
        var tenant = await FindByNameAsync(name, ct);
        if (tenant is null) return new TenantLifecycleResult.NotFound();

        if (tenant.Status == TenantStatus.PendingDeletion)
        {
            return new TenantLifecycleResult.InvalidStateTransition(tenant.Status.ToString());
        }

        tenant.Status = TenantStatus.PendingDeletion;
        tenant.PendingDeletionAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        // Phase 1 doesn't cascade-revoke refresh tokens (no TenantId column on them yet
        // — that lands in Phase 2). Phase 3 wires the revocation cascade in. Soft-delete
        // is reversible until the sweep fires, so this is safe to defer.

        _logger.LogWarning(
            SecurityEventIds.TenantSoftDeleted,
            "Tenant {TenantName} soft-deleted by PlatformAdmin {CallerUserId} (pending hard-delete sweep)",
            tenant.Name, callerUserId);

        return new TenantLifecycleResult.Success();
    }

    public async Task<TenantLifecycleResult> ForceDeleteAsync(
        string name,
        string confirmName,
        string callerUserId,
        CancellationToken ct)
    {
        var tenant = await FindByNameAsync(name, ct);
        if (tenant is null) return new TenantLifecycleResult.NotFound();

        // Confirmation match is case-sensitive; the name is canonically lowercase so
        // any case mismatch is intentional friction.
        if (!string.Equals(confirmName, tenant.Name, StringComparison.Ordinal))
        {
            return new TenantLifecycleResult.ConfirmationMismatch();
        }

        _db.Tenants.Remove(tenant);
        await _db.SaveChangesAsync(ct);

        // Critical-severity log per the SecurityEventIds doc — force-delete is rare and
        // irreversible. SIEM may want to page.
        _logger.LogCritical(
            SecurityEventIds.TenantForceDeleted,
            "Tenant {TenantName} FORCE-DELETED by PlatformAdmin {CallerUserId} (irreversible)",
            tenant.Name, callerUserId);

        return new TenantLifecycleResult.Success();
    }

    private async Task<Tenant?> FindByNameAsync(string name, CancellationToken ct)
    {
        var normalised = name.Trim().ToLowerInvariant();
        return await _db.Tenants.FirstOrDefaultAsync(t => t.Name == normalised, ct);
    }
}
