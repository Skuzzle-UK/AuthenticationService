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
    public async Task AuthService_RespondsToHealthz_OnceFixtureIsReady()
    {
        // arrange — fixture has already started everything and waited for /healthz.
        // This test asserts the harness itself: AppHost boots, containers start, the
        // auth project comes up, and we can reach it via the Aspire-allocated URL.
        using var client = _fixture.App.CreateHttpClient("auth", "https");

        // act
        var response = await client.GetAsync("/healthz");

        // assert
        response.IsSuccessStatusCode.Should().BeTrue(
            because: "the fixture's WaitForAuthServiceReadyAsync poll already saw a 200.");
    }
}