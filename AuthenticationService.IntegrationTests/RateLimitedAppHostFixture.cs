namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Variant of <see cref="AppHostFixture"/> with rate limiting <b>enabled</b>. Used by
/// scenario tests asserting on rate-limiter behaviour. Pays the same ~30s startup cost
/// as the default fixture, so kept in its own collection for the few scenarios that
/// need it.
/// </summary>
public sealed class RateLimitedAppHostFixture : AppHostFixture
{
    // Omit --rate-limiting-disabled (leaves RateLimitingEnabled at its production-default true).
    protected override string[] AppHostArgs => ["--integration-test"];
}
