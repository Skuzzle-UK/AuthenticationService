namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Parallel collection for scenarios that need a rate-limited AppHost (i.e., the
/// production-shape one). Tests joining this collection share a single
/// <see cref="RateLimitedAppHostFixture"/> instance so the second container boot is
/// paid only once, not per test class.
/// </summary>
[CollectionDefinition(Name)]
public sealed class RateLimitedIntegrationTestCollection : ICollectionFixture<RateLimitedAppHostFixture>
{
    public const string Name = "RateLimitedIntegration";
}
