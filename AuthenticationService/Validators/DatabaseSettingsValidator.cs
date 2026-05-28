using AuthenticationService.Constants;
using AuthenticationService.Settings;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Validators;

/// <summary>
/// Rejects startup if <c>DatabaseSettings.Provider</c> isn't one of the wired
/// providers. Catches typos and Phase-ahead-of-implementation misconfig (e.g. setting
/// <c>Provider = "PostgreSQL"</c> before Phase 3 has shipped).
/// </summary>
public sealed class DatabaseSettingsValidator : IValidateOptions<DatabaseSettings>
{
    public ValidateOptionsResult Validate(string? name, DatabaseSettings options)
    {
        if (name != Options.DefaultName)
        {
            return ValidateOptionsResult.Skip;
        }

        if (string.IsNullOrWhiteSpace(options.Provider))
        {
            return ValidateOptionsResult.Fail(
                "DatabaseSettings:Provider must be set. " +
                $"Supported: {string.Join(", ", DatabaseProviders.Supported)}.");
        }

        if (!DatabaseProviders.Supported.Contains(options.Provider, StringComparer.Ordinal))
        {
            return ValidateOptionsResult.Fail(
                $"DatabaseSettings:Provider '{options.Provider}' is not supported. " +
                $"Allowed values: {string.Join(", ", DatabaseProviders.Supported)}.");
        }

        return ValidateOptionsResult.Success;
    }
}
