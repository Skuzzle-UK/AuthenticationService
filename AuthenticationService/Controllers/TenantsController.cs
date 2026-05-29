using AuthenticationService.Constants;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace AuthenticationService.Controllers;

/// <summary>
/// Platform-level tenant administration. Phase 1 of the multi-tenancy plan; see
/// <c>docs/concepts/multi-tenancy-plan.md</c>.
///
/// Gated on <see cref="PolicyConstants.PlatformAdminOnly"/> — the seeded admin user
/// holds the <see cref="RolesConstants.PlatformAdmin"/> role so this controller is
/// callable from Phase 1 onwards. Phase 4 will add admin endpoints for assigning the
/// role to other users.
/// </summary>
[Route("api/[controller]")]
[ApiController]
[Authorize(Policy = PolicyConstants.PlatformAdminOnly)]
[EnableRateLimiting(RateLimitPolicies.AuthSensitive)]
public class TenantsController : ControllerBase
{
    private readonly ITenantService _tenantService;

    public TenantsController(ITenantService tenantService)
    {
        _tenantService = tenantService;
    }

    [HttpGet]
    public async Task<IActionResult> ListTenantsAsync(CancellationToken ct)
    {
        var tenants = await _tenantService.ListAsync(ct);
        return Ok(tenants);
    }

    [HttpGet("{name}")]
    public async Task<IActionResult> GetTenantAsync(string name, CancellationToken ct)
    {
        var detail = await _tenantService.GetByNameAsync(name, ct);
        if (detail is null) return NotFound();
        return Ok(detail);
    }

    [HttpPost]
    public async Task<IActionResult> CreateTenantAsync(
        [FromBody] CreateTenantDto request,
        CancellationToken ct)
    {
        var result = await _tenantService.CreateAsync(
            request.Name!, request.DisplayName!, User.GetUserIdOrEmpty(), ct);

        return result switch
        {
            CreateTenantResult.Success ok => CreatedAtAction(
                nameof(GetTenantAsync), new { name = ok.Name }, new { id = ok.TenantId, name = ok.Name }),
            CreateTenantResult.InvalidName bad => ValidationProblem(new ValidationProblemDetails(
                new Dictionary<string, string[]> { ["name"] = [bad.Reason] })),
            CreateTenantResult.NameAlreadyExists => Conflict(new ApiResponse()
                .AddError("name", "A tenant with that name already exists.")),
            _ => Problem("Unknown CreateTenantResult variant."),
        };
    }

    [HttpPost("{name}/suspend")]
    public async Task<IActionResult> SuspendTenantAsync(
        string name,
        [FromBody] SuspendTenantDto request,
        CancellationToken ct)
    {
        var result = await _tenantService.SuspendAsync(name, request.Reason!, User.GetUserIdOrEmpty(), ct);
        return MapLifecycleResult(result);
    }

    [HttpPost("{name}/unsuspend")]
    public async Task<IActionResult> UnsuspendTenantAsync(string name, CancellationToken ct)
    {
        var result = await _tenantService.UnsuspendAsync(name, User.GetUserIdOrEmpty(), ct);
        return MapLifecycleResult(result);
    }

    [HttpDelete("{name}")]
    public async Task<IActionResult> SoftDeleteTenantAsync(string name, CancellationToken ct)
    {
        var result = await _tenantService.SoftDeleteAsync(name, User.GetUserIdOrEmpty(), ct);
        return MapLifecycleResult(result);
    }

    [HttpPost("{name}/delete-now")]
    public async Task<IActionResult> ForceDeleteTenantAsync(
        string name,
        [FromBody] ForceDeleteTenantDto request,
        CancellationToken ct)
    {
        var result = await _tenantService.ForceDeleteAsync(name, request.ConfirmName!, User.GetUserIdOrEmpty(), ct);
        return MapLifecycleResult(result);
    }

    private IActionResult MapLifecycleResult(TenantLifecycleResult result) => result switch
    {
        TenantLifecycleResult.Success => NoContent(),
        TenantLifecycleResult.NotFound => NotFound(),
        TenantLifecycleResult.InvalidStateTransition bad => Conflict(new ApiResponse()
            .AddError("status", $"Tenant is currently {bad.CurrentStatus}; this operation isn't valid from that state.")),
        TenantLifecycleResult.ConfirmationMismatch => BadRequest(new ApiResponse()
            .AddError("confirmName", "Confirmation name doesn't match the tenant name.")),
        _ => Problem("Unknown TenantLifecycleResult variant."),
    };
}
