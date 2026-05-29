using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;

namespace AuthenticationService.Middleware;

/// <summary>
/// Reads the multi-tenancy claims from the authenticated principal and populates
/// <see cref="ITenantAccessor"/> for the request. Registered after JwtBearer auth so the
/// principal exists. No-op when the request is unauthenticated (login, signup, JWKS,
/// health) or when the token doesn't carry a <c>tid</c> claim (Phase 1 tokens, which is
/// every token until Phase 3 wires the claim in at issuance).
///
/// Phase 1 deliberately includes this middleware so the plumbing is in place — every
/// piece of code that depends on <see cref="ITenantAccessor"/> can be written and tested
/// without waiting for Phase 3. EF global query filters (Phase 2) and tenant-aware login
/// (Phase 3) plug into the same accessor.
///
/// Platform-admin authorization is handled by the standard role pipeline
/// (<c>[Authorize(Roles = "PlatformAdmin")]</c>) and lives on the principal's role claims
/// — this middleware doesn't reach for it.
/// </summary>
public class TenantResolutionMiddleware
{
    private readonly RequestDelegate _next;

    public TenantResolutionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ITenantAccessor tenantAccessor)
    {
        var principal = context.User;
        if (principal?.Identity?.IsAuthenticated == true)
        {
            var tenantName = principal.FindFirst(ClaimConstants.Tid)?.Value;

            // tenantId vs tenantName: Phase 1 tokens don't carry either. From Phase 3
            // onwards the `tid` claim carries the tenant Name (per Decision 3 —
            // "convention is to carry the tenant Name for human readability"). Resolution
            // from name to the canonical GUID Id happens in Phase 2 once entities have a
            // TenantId FK.
            tenantAccessor.SetTenantContext(
                tenantId: null,        // Phase 2 wires this from a name→id lookup
                tenantName: tenantName);
        }

        await _next(context);
    }
}
