namespace AuthenticationService.Shared.Constants;

/// <summary>
/// Names of the roles the service defines.
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
    /// Platform-level tenant administration (multi-tenancy Decision 5). Held by users who
    /// can create / suspend / delete tenants and act platform-wide. Stored in Identity's
    /// <c>AspNetUserRoles</c> table (i.e. not bound to any tenant membership). The seeded
    /// admin holds this role by default; further holders are assigned by existing
    /// PlatformAdmins. Distinct from <c>TenantAdmin</c> which is the per-tenant admin role
    /// stored on <c>UserTenantMembershipRole</c>.
    /// </summary>
    public const string PlatformAdmin = "PlatformAdmin";

    /// <summary>
    /// Upper-case forms used for Identity's <c>NormalizedName</c> column when seeding
    /// role rows via EF rather than <c>RoleManager</c>.
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

        /// <summary>
        /// Normalised form of <see cref="RolesConstants.PlatformAdmin"/>.
        /// </summary>
        public const string PlatformAdmin = "PLATFORMADMIN";
    }
}
