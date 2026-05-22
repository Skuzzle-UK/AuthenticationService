using AuthenticationService.Settings;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Validators;

/// <summary>
/// Refuses to start outside Development if <see cref="ForwardedHeadersSettings.KnownNetworks"/>
/// AND <see cref="ForwardedHeadersSettings.KnownProxies"/> are both empty. When both lists
/// are empty the ForwardedHeaders middleware ignores <c>X-Forwarded-For</c> entirely — so
/// audit logs record the LB IP instead of the real client and the rate limiter buckets the
/// entire cluster's traffic under that single IP. Both failure modes are silent at runtime.
/// </summary>
public sealed class ForwardedHeadersSettingsValidator : IValidateOptions<ForwardedHeadersSettings>
{
    private readonly IHostEnvironment _environment;

    public ForwardedHeadersSettingsValidator(IHostEnvironment environment)
    {
        _environment = environment;
    }

    public ValidateOptionsResult Validate(string? name, ForwardedHeadersSettings options)
    {
        if (name != Options.DefaultName)
        {
            return ValidateOptionsResult.Skip;
        }

        if (_environment.IsDevelopment())
        {
            return ValidateOptionsResult.Success;
        }

        if (options.KnownNetworks.Count == 0 && options.KnownProxies.Count == 0)
        {
            return ValidateOptionsResult.Fail(
                "ForwardedHeadersSettings has no KnownNetworks or KnownProxies configured. " +
                "Outside Development this means X-Forwarded-For is ignored and every request " +
                "appears to come from the load balancer — audit logs lose the real client IP " +
                "and rate-limit buckets collapse to a single cluster-wide bucket. " +
                "Populate ForwardedHeadersSettings:KnownNetworks (CIDR) or " +
                "ForwardedHeadersSettings:KnownProxies (single IP) via appsettings.json, env " +
                "var, or secret store before deploying.");
        }

        return ValidateOptionsResult.Success;
    }
}
