using AuthenticationService.Shared.Constants;

namespace AuthenticationService.Services;

/// <summary>
/// Decides whether a caller holding a given set of roles is permitted to assign each of
/// a requested set of target roles. Centralised so every code path that calls
/// <c>UserManager.AddToRoleAsync</c> with caller-controlled input flows through the same
/// allow-list — defence in depth on top of the endpoint-level <c>[Authorize]</c> gate.
///
/// Rules (multi-tenancy Decision 5):
/// <list type="bullet">
///   <item><see cref="RolesConstants.Admin"/> — seed-only. Never assignable via API.</item>
///   <item><see cref="RolesConstants.PlatformAdmin"/> — only assignable by an existing
///     PlatformAdmin (prevents privilege escalation: an <c>Admin</c>-policy caller cannot
///     elevate themselves or anyone else to platform scope).</item>
///   <item>Other (non-elevated) roles — assignable by any <c>Admin</c> or
///     <c>PlatformAdmin</c>.</item>
/// </list>
/// </summary>
public interface IRoleAssignmentPolicy
{
    /// <summary>
    /// Returns the subset of <paramref name="targetRoles"/> the caller is not permitted
    /// to assign. Empty when every requested role is allowed.
    /// </summary>
    IReadOnlyList<string> Forbidden(
        IReadOnlyCollection<string> callerRoles,
        IEnumerable<string> targetRoles);
}

/// <inheritdoc />
public sealed class RoleAssignmentPolicy : IRoleAssignmentPolicy
{
    public IReadOnlyList<string> Forbidden(
        IReadOnlyCollection<string> callerRoles,
        IEnumerable<string> targetRoles)
    {
        var hasAdmin = callerRoles.Contains(RolesConstants.Admin, StringComparer.Ordinal);
        var hasPlatformAdmin = callerRoles.Contains(RolesConstants.PlatformAdmin, StringComparer.Ordinal);

        var forbidden = new List<string>();
        foreach (var role in targetRoles)
        {
            if (string.Equals(role, RolesConstants.Admin, StringComparison.Ordinal))
            {
                // Admin is seed-only. No caller — not even a PlatformAdmin — may grant it
                // through the API; doing so would create an alternative escalation path
                // out of PlatformAdmin scope and into the AdminController surface.
                forbidden.Add(role);
                continue;
            }

            if (string.Equals(role, RolesConstants.PlatformAdmin, StringComparison.Ordinal))
            {
                if (!hasPlatformAdmin)
                {
                    forbidden.Add(role);
                }
                continue;
            }

            // Non-elevated roles. Any caller in Admin or PlatformAdmin may assign.
            // (Callers with neither don't reach role-assignment endpoints because of the
            // controller-level [Authorize] gate, but the check is still done here so the
            // policy holds even if a future endpoint forgets the attribute.)
            if (!hasAdmin && !hasPlatformAdmin)
            {
                forbidden.Add(role);
            }
        }

        return forbidden;
    }
}
