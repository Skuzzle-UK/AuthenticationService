namespace AuthenticationService.Shared.Constants;

/// <summary>
/// Names of the roles the service defines. Use these instead of magic strings when
/// assigning roles to a user or checking role membership.
/// </summary>
public static class RolesConstants
{
    /// <summary>
    /// Highest privilege level. Granted to the seeded admin user.
    /// </summary>
    public const string Admin = "Admin";

    /// <summary>
    /// Default role assigned to every newly-registered user.
    /// </summary>
    public const string DefaultUser = "DefaultUser";

    /// <summary>
    /// Upper-case versions of the role names. ASP.NET Core Identity stores roles in two
    /// columns — the display name and a normalised (upper-case) version used for
    /// indexed lookups. When seeding role rows directly via EF (rather than going through
    /// <c>RoleManager</c>), use these for the <c>NormalizedName</c> column.
    /// </summary>
    public static class Normalised
    {
        /// <summary>
        /// Normalised form of <see cref="RolesConstants.Admin"/>.
        /// </summary>
        public const string Admin = "ADMIN";

        /// <summary>
        /// Normalised form of <see cref="RolesConstants.DefaultUser"/>.
        /// </summary>
        public const string DefaultUser = "DEFAULTUSER";
    }
}
