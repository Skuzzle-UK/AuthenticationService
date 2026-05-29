using System.Security.Claims;
using AuthenticationService.Shared.Constants;

namespace AuthenticationService.Shared.Extensions;

/// <summary>
/// Convenience reads against the principal built from a JWT issued by this service.
/// Lives in <c>AuthenticationService.Shared</c> so both the issuer (the auth service) and
/// any downstream consumer (via <c>TokenValidationLib</c>) can reach for the same helpers
/// without re-implementing the claim lookups.
/// </summary>
public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Reads the user id from the standard JWT <see cref="ClaimConstants.Sub"/> claim.
    /// Returns null when the principal is unauthenticated or the claim is missing —
    /// callers that need a non-null fallback (e.g. for audit-log enrichment) should
    /// use <see cref="GetUserIdOrEmpty"/> instead.
    /// </summary>
    /// <remarks>
    /// Note that this is purely a read against the JWT — it performs no authorization.
    /// Role / policy checks happen at the <c>[Authorize]</c> attribute on the action,
    /// before the call reaches the controller body.
    /// </remarks>
    public static string? GetUserId(this ClaimsPrincipal principal) =>
        principal.FindFirst(ClaimConstants.Sub)?.Value;

    /// <summary>
    /// As <see cref="GetUserId"/> but coalesces a missing claim to <see cref="string.Empty"/>.
    /// Convenience for audit-log enrichment fields that expect non-null strings: by the
    /// time an action body runs, <c>[Authorize]</c> has already verified the principal is
    /// authenticated, so a missing sub claim indicates a malformed token rather than an
    /// anonymous caller — empty string is a defensive fallback rather than a real case.
    /// </summary>
    public static string GetUserIdOrEmpty(this ClaimsPrincipal principal) =>
        principal.GetUserId() ?? string.Empty;

    /// <summary>
    /// Reads the tenant id from the <see cref="ClaimConstants.Tid"/> claim (multi-tenancy
    /// Decision 3). Returns null on platform-admin tokens that aren't tenant-bound, or on
    /// any token issued before Phase 3 wires the claim in.
    /// </summary>
    public static string? GetTenantId(this ClaimsPrincipal principal) =>
        principal.FindFirst(ClaimConstants.Tid)?.Value;

    /// <summary>
    /// Snapshots every <see cref="ClaimConstants.Role"/> claim on the principal as a
    /// materialised collection. Complements ASP.NET Core's <see cref="ClaimsPrincipal.IsInRole(string)"/>
    /// (which only answers about a single role) for cases where the caller needs the full
    /// role set — e.g. feeding <c>IRoleAssignmentPolicy</c> or rendering "my permissions"
    /// in a /me endpoint. Returns an empty array for an unauthenticated or role-free
    /// principal; never null.
    /// </summary>
    public static IReadOnlyCollection<string> GetRoles(this ClaimsPrincipal principal) =>
        principal.FindAll(ClaimConstants.Role).Select(c => c.Value).ToArray();
}
