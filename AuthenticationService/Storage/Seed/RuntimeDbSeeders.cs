using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Storage.Seed;

public static class RuntimeDbSeeders
{
    public static WebApplication RuntimeDbSeed(this WebApplication app)
    {
        app.SeedAdministratorAccount();
        return app;
    }

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
