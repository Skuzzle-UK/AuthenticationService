using Aspire.Hosting.Testing;
using AwesomeAssertions;

namespace AuthenticationService.IntegrationTests;

[Collection(IntegrationTestCollection.Name)]
public class HarnessSmokeTests
{
    private readonly AppHostFixture _fixture;

    public HarnessSmokeTests(AppHostFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task AuthService_RespondsToReadyz_OnceFixtureIsReady()
    {
        // Asserts the harness itself: AppHost boots, containers start, auth project
        // reachable with its dependencies (MySQL, Redis) up.
        using var client = _fixture.App.CreateHttpClient("auth", "http");

        var response = await client.GetAsync("/readyz");

        response.IsSuccessStatusCode.Should().BeTrue(
            because: "the fixture's WaitForAuthServiceReadyAsync poll already saw a 200.");
    }
}
