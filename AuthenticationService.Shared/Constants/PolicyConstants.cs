namespace AuthenticationService.Shared.Constants;

/// <summary>
/// Names of the ASP.NET Core authorisation policies registered by this service and
/// available to consumers. Apply via <c>[Authorize(Policy = PolicyConstants.AdminOnly)]</c>
/// on actions that need admin access.
/// </summary>
public static class PolicyConstants
{
    /// <summary>
    /// Restricts the action to users in the <see cref="RolesConstants.Admin"/> role.
    /// </summary>
    public const string AdminOnly = "AdminOnly";
}