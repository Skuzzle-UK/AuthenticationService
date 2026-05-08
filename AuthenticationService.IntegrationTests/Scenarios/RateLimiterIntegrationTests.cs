using System.Net;
using System.Net.Http.Json;
using AuthenticationService.Shared.Dtos;
using AwesomeAssertions;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// <para><b>Scenario 5 — Rate-limiter integration.</b></para>
///
/// <para>Asserts that the rate limiter actually fires under realistic burst traffic
/// against a real Redis. Joins <see cref="RateLimitedIntegrationTestCollection"/> so it
/// runs against a separate AppHost where <c>HostingSettings:RateLimitingEnabled</c> is
/// left at its production default of <c>true</c> — the rest of the integration tests
/// disable rate limiting so back-to-back scenario calls don't trip it.</para>
///
/// <para>What this catches that unit tests can't:</para>
/// <list type="bullet">
///   <item><description>The Redis-backed limiter actually executes its Lua scripts against a real Redis (the <c>RedisRateLimiting</c> library uses Lua for atomic INCR + EXPIRE — fakes don't exercise that).</description></item>
///   <item><description>The limiter is wired into the request pipeline at the right place. Unit tests verify the configurator builds policies; only an end-to-end test confirms middleware actually consults them.</description></item>
///   <item><description>The chained-pipeline composition (Redis primary + in-memory fallback) is correctly composed by <c>PartitionedRateLimiter.CreateChained</c> — a regression there would silently disable rate limiting cluster-wide.</description></item>
/// </list>
/// </summary>
[Collection(RateLimitedIntegrationTestCollection.Name)]
public class RateLimiterIntegrationTests(RateLimitedAppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task GlobalLimiter_TripsUnderBurstFromSameIp()
    {
        // arrange — burst attempts with bogus credentials. We deliberately don't pre-
        // create a user; the global limiter is per-IP and triggers regardless of
        // whether the email exists. The 4/10s cap means somewhere in the first ~5
        // attempts we'll start seeing 429.
        var bogusEmail = UniqueEmail();
        var bogusPassword = "AnyPassword123!";

        // act — fire 6 requests as fast as possible. With a 4/10s cap and assuming
        // sub-second response times, attempts 5+ should return 429.
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 6; i++)
        {
            var response = await AuthClient.PostAsJsonAsync(
                "/api/Authentication/authenticate",
                new AuthenticationDto { Email = bogusEmail, Password = bogusPassword });
            statuses.Add(response.StatusCode);
        }

        // assert — at least one of the 6 attempts must have been rate-limited. The
        // exact count depends on response timing (slow responses give the window time
        // to reset slightly) but the 5th hit at the latest must be 429 under any
        // realistic timing.
        statuses.Should().Contain(
            HttpStatusCode.TooManyRequests,
            because: "the global rate limiter caps at 4 requests per 10 seconds per IP. " +
                     $"6 burst hits from the same IP must trip it; got status sequence: [{string.Join(", ", statuses)}].");

        // sanity — the *first* attempt should not be 429. If it were, something other
        // than rate-limiting is wrong (rate limiter pre-blocking, Redis broken, etc.)
        // and the test is misleading us by passing the contains-429 check via a
        // false-positive on the first hit.
        statuses[0].Should().NotBe(
            HttpStatusCode.TooManyRequests,
            because: "the first request in a fresh window should always pass the limiter — a 429 here would mean the limiter is misconfigured or Redis is broken, not that 'rate limiting works.'");
    }
}
