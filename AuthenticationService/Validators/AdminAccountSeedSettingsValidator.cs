using AuthenticationService.Settings;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Validators;

/// <summary>
/// Refuses to start outside Development if the seed-admin password is the well-known dev default — guards against operators copying appsettings.Development.json without changing the password.
/// </summary>
public sealed class AdminAccountSeedSettingsValidator : IValidateOptions<AdminAccountSeedSettings>
{
    // Kept in sync with appsettings.Development.json by hand — change both together.
    private const string DevDefaultPassword = "Pa5$word123-dev";

    private readonly IHostEnvironment _environment;

    public AdminAccountSeedSettingsValidator(IHostEnvironment environment)
    {
        _environment = environment;
    }

    public ValidateOptionsResult Validate(string? name, AdminAccountSeedSettings options)
    {
        // Only validate the default-named instance — named-options callers opt into their own validator.
        if (name != Options.DefaultName)
        {
            return ValidateOptionsResult.Skip;
        }

        if (_environment.IsDevelopment())
        {
            return ValidateOptionsResult.Success;
        }

        if (string.Equals(options.Password, DevDefaultPassword, StringComparison.Ordinal))
        {
            return ValidateOptionsResult.Fail(
                "AdminAccountSeedSettings:Password is set to the well-known development default. " +
                "Provide a real password via env var, user-secrets, or a secret store " +
                "(e.g. AdminAccountSeedSettings__Password=<value>) before deploying outside Development.");
        }

        return ValidateOptionsResult.Success;
    }
}
