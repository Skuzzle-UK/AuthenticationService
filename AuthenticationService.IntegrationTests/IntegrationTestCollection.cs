namespace AuthenticationService.IntegrationTests;

/// <summary>
/// xUnit instantiates one <see cref="AppHostFixture"/> per collection — every test class
/// joining this collection shares the same fixture, so we pay the container-startup cost
/// once for the whole suite.
/// </summary>
[CollectionDefinition(Name)]
public sealed class IntegrationTestCollection : ICollectionFixture<AppHostFixture>
{
    public const string Name = "Integration";
}