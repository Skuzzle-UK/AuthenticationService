using System.Net;
using System.Net.Http.Json;
using AuthenticationService.Shared.Dtos;
using AwesomeAssertions;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// Scenario 5 — Rate-limiter integration. Asserts the limiter fires under burst traffic
/// against a real Redis (joins the rate-limited collection where the AppHost runs with
/// limiting enabled). Catches regressions in the Lua-script execution, request-pipeline
/// wiring, and chained-limiter composition that unit tests can't see.
/// </summary>
[Collection(RateLimitedIntegrationTestCollection.Name)]
public class RateLimiterIntegrationTests(RateLimitedAppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task GlobalLimiter_TripsUnderBurstFromSameIp()
    {
        // No pre-created user — the global limiter is per-IP and triggers regardless
        // of whether the email exists.
        var bogusEmail = UniqueEmail();
        var bogusPassword = "AnyPassword123!";

        // 6 requests against a 4/10s cap — attempts 5+ should be 429.
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 6; i++)
        {
            var response = await AuthClient.PostAsJsonAsync(
                "/api/Authentication/authenticate",
                new AuthenticationDto { Email = bogusEmail, Password = bogusPassword });
            statuses.Add(response.StatusCode);
        }

        statuses.Should().Contain(
            HttpStatusCode.TooManyRequests,
            because: "the global rate limiter caps at 4 requests per 10 seconds per IP. " +
                     $"6 burst hits from the same IP must trip it; got status sequence: [{string.Join(", ", statuses)}].");

        // Guard against a false-positive contains-429 from a misconfigured limiter
        // blocking the very first request.
        statuses[0].Should().NotBe(
            HttpStatusCode.TooManyRequests,
            because: "the first request in a fresh window should always pass the limiter — a 429 here would mean the limiter is misconfigured or Redis is broken, not that 'rate limiting works.'");
    }
}
