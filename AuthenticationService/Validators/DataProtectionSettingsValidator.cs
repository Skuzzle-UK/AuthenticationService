using AuthenticationService.Settings;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Validators;

/// <summary>
/// Refuses to start outside Development if <see cref="DataProtectionSettings.Certificate"/>'s
/// <c>PfxPath</c> is missing. Without the cert the data-protection key ring sits in Redis as
/// readable XML — anyone with read access to that Redis instance can extract the keys and
/// forge anti-forgery tokens, decrypt protected payloads (Identity password-reset / email-
/// confirmation / MFA tokens) offline, and so on. Development is allowed to skip the cert
/// so <c>dotnet run</c> works first time.
/// </summary>
public sealed class DataProtectionSettingsValidator : IValidateOptions<DataProtectionSettings>
{
    private readonly IHostEnvironment _environment;

    public DataProtectionSettingsValidator(IHostEnvironment environment)
    {
        _environment = environment;
    }

    public ValidateOptionsResult Validate(string? name, DataProtectionSettings options)
    {
        if (name != Options.DefaultName)
        {
            return ValidateOptionsResult.Skip;
        }

        if (_environment.IsDevelopment())
        {
            return ValidateOptionsResult.Success;
        }

        if (string.IsNullOrWhiteSpace(options.Certificate?.PfxPath))
        {
            return ValidateOptionsResult.Fail(
                "DataProtectionSettings:Certificate:PfxPath is required outside Development. " +
                "Without a certificate the data-protection key ring is persisted to Redis as " +
                "readable XML — anyone with read access to that Redis instance can extract the " +
                "keys and forge Identity tokens (password reset, email confirmation, MFA) offline. " +
                "Provide a PFX path via appsettings.json, env var, or secret store " +
                "(e.g. DataProtectionSettings__Certificate__PfxPath=/run/secrets/data-protection.pfx) " +
                "before deploying.");
        }

        return ValidateOptionsResult.Success;
    }
}
