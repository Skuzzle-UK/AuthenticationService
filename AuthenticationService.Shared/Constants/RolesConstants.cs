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
    }
}
