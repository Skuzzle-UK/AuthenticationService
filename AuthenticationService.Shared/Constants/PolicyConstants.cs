namespace AuthenticationService.Shared.Constants;

/// <summary>
/// Names of the ASP.NET Core authorisation policies registered by this service. Use with
/// <c>[Authorize(Policy = PolicyConstants.AdminOnly)]</c>.
/// </summary>
public static class PolicyConstants
{
    /// <summary>
    /// Restricts the action to users in the <see cref="RolesConstants.Admin"/> role.
    /// </summary>
    public const string AdminOnly = "AdminOnly";

    /// <summary>
    /// Restricts the action to users in the <see cref="RolesConstants.PlatformAdmin"/>
    /// role (multi-tenancy Decision 5). Used on <c>TenantsController</c> and any future
    /// cross-tenant management endpoint.
    /// </summary>
    public const string PlatformAdminOnly = "PlatformAdminOnly";
}
