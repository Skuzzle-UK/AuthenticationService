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
        //
        // Use the http endpoint to match how every other test reaches the auth service.
        // Tests run with HostingSettings:HttpsRedirectionEnabled=false (set by the
        // AppHost when the --integration-test arg is passed) so the http endpoint is
        // the canonical transport in test mode.
        using var client = _fixture.App.CreateHttpClient("auth", "http");

        // act
        var response = await client.GetAsync("/healthz");

        // assert
        response.IsSuccessStatusCode.Should().BeTrue(
            because: "the fixture's WaitForAuthServiceReadyAsync poll already saw a 200.");
    }
}