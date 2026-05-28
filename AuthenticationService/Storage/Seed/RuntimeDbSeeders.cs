using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Storage.Seed;

/// <summary>
/// Runtime DB seeding — rows that need <c>UserManager</c> and can't be expressed as static
/// EF data. Currently just the default admin account.
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
    /// is required (validated at startup) outside Development. If
    /// <see cref="AdminAccountSeedSettings.ResetOnStartup"/> is on, an existing admin is
    /// reset via <see cref="ResetAdministratorAccountAsync"/> instead.
    /// </summary>
    public static async Task<WebApplication> SeedAdministratorAccountAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
        var dbContext = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        var settings = scope.ServiceProvider.GetRequiredService<IOptions<AdminAccountSeedSettings>>().Value;
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("RuntimeDbSeeders");

        try
        {
            var existing = await userManager.FindByNameAsync(UserConstants.Admin);
            if (existing is not null)
            {
                if (settings.ResetOnStartup)
                {
                    logger.LogWarning(
                        "AdminAccountSeedSettings:ResetOnStartup is enabled — applying recovery reset to {UserName}. " +
                        "Unset the flag before the next restart or every restart will keep resetting the admin.",
                        UserConstants.Admin);
                    await ResetAdministratorCoreAsync(existing, userManager, dbContext, settings, logger);
                }
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
        catch (ArgumentException)
        {
            // Misconfigured admin settings — message already self-describing.
            throw;
        }
        catch (Exception ex) when (IsTransientDatabaseError(ex))
        {
            logger.LogCritical(
                ex,
                "Runtime DB seeding failed because the database is unreachable. " +
                "Check ConnectionStrings:DefaultConnection and that the DB host accepts " +
                "connections from this replica. Failing startup so the orchestrator reschedules.");
            throw;
        }
        catch (Exception ex)
        {
            logger.LogCritical(
                ex,
                "Runtime DB seeding failed unexpectedly. If the database is unreachable, " +
                "the orchestrator should reschedule on its own; otherwise investigate the " +
                "seed configuration and migration state. Failing startup.");
            throw;
        }
    }

    /// <summary>
    /// Break-glass recovery entry point — called by the CLI subcommand
    /// (<c>dotnet run -- reset-admin</c>). Reads <see cref="AdminAccountSeedSettings"/>
    /// and applies the same reset the <c>ResetOnStartup</c> flag would, then exits.
    /// Use when the admin account is locked / MFA-stuck / password-lost and you have
    /// shell access but can't bounce the service. See docs/operations/admin-recovery.md.
    /// </summary>
    public static async Task<IHost> ResetAdministratorAccountAsync(this IHost host)
    {
        using var scope = host.Services.CreateScope();

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
        var dbContext = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        var settings = scope.ServiceProvider.GetRequiredService<IOptions<AdminAccountSeedSettings>>().Value;
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("RuntimeDbSeeders");

        var user = await userManager.FindByNameAsync(UserConstants.Admin);
        if (user is null)
        {
            logger.LogWarning(
                "Admin reset requested but {UserName} doesn't exist. Run normal startup to seed it first.",
                UserConstants.Admin);
            return host;
        }

        await ResetAdministratorCoreAsync(user, userManager, dbContext, settings, logger);
        return host;
    }

    // Shared reset logic. Both entry points (ResetOnStartup-flag path and CLI path)
    // funnel through here. Not transactional — each step is a separate DB write — but
    // each step is idempotent so a partial failure can be safely retried by running the
    // reset again.
    private static async Task ResetAdministratorCoreAsync(
        User user,
        UserManager<User> userManager,
        DatabaseContext dbContext,
        AdminAccountSeedSettings settings,
        ILogger logger)
    {
        // 1. Clear lockout state and the access-failed counter.
        await userManager.SetLockoutEndDateAsync(user, lockoutEnd: null);
        await userManager.ResetAccessFailedCountAsync(user);

        // 2. Re-confirm email so login isn't gated on a stale email-confirmation state.
        if (!user.EmailConfirmed)
        {
            user.EmailConfirmed = true;
            await userManager.UpdateAsync(user);
        }

        // 3. Reset the password through Identity's validation pipeline — weak passwords
        //    still fail (CustomPasswordValidator, length, etc.). Updates security stamp.
        var resetToken = await userManager.GeneratePasswordResetTokenAsync(user);
        var resetResult = await userManager.ResetPasswordAsync(user, resetToken, settings.Password);
        if (!resetResult.Succeeded)
        {
            var errors = string.Join("; ", resetResult.Errors.Select(e => $"{e.Code}: {e.Description}"));
            throw new InvalidOperationException(
                $"Admin password reset failed: {errors}. Check AdminAccountSeedSettings:Password meets the password policy.");
        }

        // 4. Disable MFA so the operator can log in without the authenticator app.
        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            await userManager.SetTwoFactorEnabledAsync(user, false);
        }

        // 5. Re-ensure role membership in case it was somehow lost.
        if (!await userManager.IsInRoleAsync(user, RolesConstants.Admin))
        {
            await userManager.AddToRoleAsync(user, RolesConstants.Admin);
        }
        if (!await userManager.IsInRoleAsync(user, RolesConstants.DefaultUser))
        {
            await userManager.AddToRoleAsync(user, RolesConstants.DefaultUser);
        }

        // 6. Revoke all active refresh tokens — forces re-login from every device.
        await dbContext.RefreshTokens
            .Where(t => t.UserId == user.Id && t.ConsumedAt == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.ConsumedAt, DateTimeOffset.UtcNow)
                .SetProperty(t => t.RevocationReason, RevocationReasons.AdminRecovery));

        // 7. Rotate the security stamp — kills any still-live access tokens immediately
        //    (ResetPasswordAsync also rotates it, but this is belt-and-braces).
        await userManager.UpdateSecurityStampAsync(user);

        logger.LogCritical(
            SecurityEventIds.AdminAccountRecovered,
            "Admin account recovery applied to {UserName} ({UserId}). " +
            "Password reset, lockout cleared, MFA disabled, refresh tokens revoked, " +
            "security stamp rotated.",
            user.UserName,
            user.Id);
    }

    private static bool IsSeederRaceLoss(IEnumerable<IdentityError> errors) =>
        errors.All(e => e.Code is DuplicateUserNameErrorCode or DuplicateEmailErrorCode);

    // Walks the inner-exception chain for DB-connectivity smells.
    private static bool IsTransientDatabaseError(Exception ex)
    {
        for (var current = ex; current is not null; current = current.InnerException)
        {
            if (current is System.Data.Common.DbException)
            {
                return true;
            }

            if (current is TimeoutException)
            {
                return true;
            }

            var typeName = current.GetType().FullName ?? string.Empty;
            if (typeName.StartsWith("MySqlConnector.", StringComparison.Ordinal)
                || typeName.StartsWith("MySql.Data.", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
