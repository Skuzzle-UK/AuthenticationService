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
    /// <summary>Runs every runtime seeder. Called once at startup.</summary>
    public static WebApplication RuntimeDbSeed(this WebApplication app)
    {
        app.SeedAdministratorAccount();
        return app;
    }

    /// <summary>
    /// Creates the default administrator account on first startup if it doesn't already
    /// exist. Credentials come from <see cref="AdminAccountSeedSettings"/> — the password
    /// is required (validated at startup) outside Development.
    /// </summary>
    public static WebApplication SeedAdministratorAccount(this WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var settings = scope.ServiceProvider.GetRequiredService<IOptions<AdminAccountSeedSettings>>().Value;
            var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("RuntimeDbSeeders");

            if (userManager.FindByNameAsync(UserConstants.Admin).Result == null)
            {
                var result = userManager.CreateAsync(
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
                    settings.Password
                ).Result;

                if (!result.Succeeded)
                {
                    var exceptionMessage = $"AdminAccountSeedSettings is configured incorrectly: ";
                    foreach (var error in result.Errors)
                    {
                        exceptionMessage += $"{error.Description} ";
                    }

                    throw new ArgumentException(exceptionMessage);
                }

                var user = userManager.FindByEmailAsync(settings.Email).Result;
                userManager.AddToRoleAsync(user!, RolesConstants.Admin).Wait();
                userManager.AddToRoleAsync(user!, RolesConstants.DefaultUser).Wait();

                logger.LogInformation(
                    "Seeded administrator account {UserName} ({UserId}).",
                    UserConstants.Admin,
                    user!.Id);
            }
        }

        return app;
    }
}
