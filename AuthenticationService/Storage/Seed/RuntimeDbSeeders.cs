using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Storage.Seed;

/// <summary>
/// Seeds rows into the database that have to be there for the service to be usable, but
/// can't be expressed as static EF data (because they need access to runtime services like
/// <c>UserManager</c>). Currently just the default administrator account.
/// </summary>
public static class RuntimeDbSeeders
{
    private const string DuplicateUserNameErrorCode = "DuplicateUserName";
    private const string DuplicateEmailErrorCode = "DuplicateEmail";

    /// <summary>
    /// Runs every runtime seeder. Called once at startup.
    /// </summary>
    public static async Task<WebApplication> RuntimeDbSeedAsync(this WebApplication app)
    {
        await app.SeedAdministratorAccountAsync();
        return app;
    }

    /// <summary>
    /// Creates the default administrator account on first startup if it doesn't already
    /// exist. Credentials come from <see cref="AdminAccountSeedSettings"/> — the password
    /// is required (validated at startup) outside Development.
    /// </summary>
    public static async Task<WebApplication> SeedAdministratorAccountAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
        var settings = scope.ServiceProvider.GetRequiredService<IOptions<AdminAccountSeedSettings>>().Value;
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("RuntimeDbSeeders");

        if (await userManager.FindByNameAsync(UserConstants.Admin) is not null)
        {
            return app;
        }

        var result = await userManager.CreateAsync(
            new User
            {
                UserName = UserConstants.Admin,
                FirstName = settings.FirstName,
                LastName = settings.LastName,
                Email = settings.Email,
                EmailConfirmed = true,
                PhoneNumber = settings.PhoneNumber,
                PhoneNumberConfirmed = settings.PhoneNumberConfirmed,
                Country = settings.Country,
            },
            settings.Password);

        if (!result.Succeeded)
        {
            if (IsSeederRaceLoss(result.Errors))
            {
                logger.LogInformation(
                    "Administrator seeding skipped — another replica seeded the account first.");
                return app;
            }

            var exceptionMessage = "AdminAccountSeedSettings is configured incorrectly: ";
            foreach (var error in result.Errors)
            {
                exceptionMessage += $"{error.Description} ";
            }

            throw new ArgumentException(exceptionMessage);
        }

        var user = await userManager.FindByEmailAsync(settings.Email);
        await userManager.AddToRoleAsync(user!, RolesConstants.Admin);
        await userManager.AddToRoleAsync(user!, RolesConstants.DefaultUser);

        logger.LogInformation(
            "Seeded administrator account {UserName} ({UserId}).",
            UserConstants.Admin,
            user!.Id);

        return app;
    }

    private static bool IsSeederRaceLoss(IEnumerable<IdentityError> errors) =>
        errors.All(e => e.Code is DuplicateUserNameErrorCode or DuplicateEmailErrorCode);
}
