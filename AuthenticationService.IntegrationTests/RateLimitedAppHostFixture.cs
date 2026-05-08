namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Variant of <see cref="AppHostFixture"/> that runs the AppHost in production-shape
/// configuration with rate limiting <b>enabled</b>. Used exclusively by scenario tests
/// that need to assert on rate-limiter behaviour — the default fixture turns it off so
/// the bulk of scenarios don't trip the global 4/10s cap when running back-to-back.
///
/// <para>Pays the same ~30s container-startup cost as the default fixture, so we keep
/// the rate-limited tests in their own collection and accept the extra boot time only
/// for the small number of scenarios that need it.</para>
/// </summary>
public sealed class RateLimitedAppHostFixture : AppHostFixture
{
    /// <summary>
    /// Passes <c>--integration-test</c> (so HTTPS redirection is off and tests can reach
    /// the auth service over HTTP — same as the default fixture) but deliberately omits
    /// <c>--rate-limiting-disabled</c>, leaving <c>HostingSettings:RateLimitingEnabled</c>
    /// at its production default of <c>true</c>.
    /// </summary>
    protected override string[] AppHostArgs => ["--integration-test"];
}
