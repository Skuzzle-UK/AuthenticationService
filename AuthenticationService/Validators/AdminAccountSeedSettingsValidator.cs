using AuthenticationService.Settings;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Validators;

/// <summary>
/// Belt-and-braces validation for <see cref="AdminAccountSeedSettings"/> beyond the
/// <c>[Required]</c> attribute already enforced by <c>ValidateDataAnnotations()</c>.
///
/// <para>The single rule that matters: outside Development, refuse to start if the password
/// is the well-known dev default. That's the realistic failure mode — an operator copies
/// <c>appsettings.Development.json</c> into a non-dev environment without changing it, or
/// forgets to set <c>AdminAccountSeedSettings__Password</c> via env var / secret store.
/// Identity's own password-complexity rules at user-creation time catch weak-but-not-default
/// choices, so this validator deliberately doesn't maintain a generic deny-list.</para>
/// </summary>
public sealed class AdminAccountSeedSettingsValidator : IValidateOptions<AdminAccountSeedSettings>
{
    /// <summary>The dev-only default that ships in <c>appsettings.Development.json</c>.
    /// Kept in sync with that file by hand — if you change one, change the other.</summary>
    private const string DevDefaultPassword = "Pa5$word123-dev";

    private readonly IHostEnvironment _environment;

    public AdminAccountSeedSettingsValidator(IHostEnvironment environment)
    {
        _environment = environment;
    }

    public ValidateOptionsResult Validate(string? name, AdminAccountSeedSettings options)
    {
        // Only validate the default-named instance. Named-options support isn't used for
        // these settings today; if a future caller introduces named instances they can opt
        // into their own validator rather than inheriting this rule.
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
