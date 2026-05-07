using AuthenticationService.Services.HealthChecks;
using AwesomeAssertions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using NSubstitute;
using StackExchange.Redis;

namespace AuthenticationService.Tests.Services.HealthChecks;

/// <summary>
/// <para><see cref="RedisHealthCheck"/> wraps the multiplexer's <c>PingAsync</c> with a
/// 1-second timeout. Three paths:</para>
/// <list type="bullet">
///   <item><description>Ping returns within timeout → Healthy with the documented message.</description></item>
///   <item><description>Ping throws (connection refused, RedisException) → Unhealthy with the exception attached.</description></item>
///   <item><description>Ping never completes within timeout → Unhealthy (the linked CTS cancels the wait).</description></item>
/// </list>
/// </summary>
public class RedisHealthCheckTests
{
    [Fact]
    public async Task CheckHealth_PingSucceeds_ReturnsHealthy()
    {
        // arrange — mock the multiplexer to return a database whose PingAsync completes
        // immediately. The exact ping value doesn't matter (we ignore it).
        var redis = Substitute.For<IConnectionMultiplexer>();
        var db = Substitute.For<IDatabase>();
        redis.GetDatabase().Returns(db);
        db.PingAsync().Returns(TimeSpan.FromMilliseconds(5));
        var check = new RedisHealthCheck(redis);

        // act
        var result = await check.CheckHealthAsync(new HealthCheckContext());

        // assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Be("Redis reachable.");
    }

    [Fact]
    public async Task CheckHealth_PingThrows_ReturnsUnhealthyWithException()
    {
        // arrange — connection refused, etc. Surface as Unhealthy so K8s readiness
        // probe pulls the pod from Service rotation until Redis recovers.
        var redis = Substitute.For<IConnectionMultiplexer>();
        var db = Substitute.For<IDatabase>();
        redis.GetDatabase().Returns(db);
        var failure = new RedisConnectionException(ConnectionFailureType.UnableToConnect, "no route to host");
        db.PingAsync().Returns<Task<TimeSpan>>(_ => throw failure);
        var check = new RedisHealthCheck(redis);

        // act
        var result = await check.CheckHealthAsync(new HealthCheckContext());

        // assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Be("Redis unreachable.");
        result.Exception.Should().BeSameAs(failure);
    }

    [Fact]
    public async Task CheckHealth_PingHangsBeyondTimeout_ReturnsUnhealthy()
    {
        // arrange — Ping never completes (e.g., Redis is up but blocked on a slow
        // command). The 1-second timeout via linked CTS turns the wait into a
        // TaskCanceledException, which the catch block translates to Unhealthy.
        var redis = Substitute.For<IConnectionMultiplexer>();
        var db = Substitute.For<IDatabase>();
        redis.GetDatabase().Returns(db);
        // Async TCS that never completes.
        var hangingTask = new TaskCompletionSource<TimeSpan>().Task;
        db.PingAsync().Returns(hangingTask);
        var check = new RedisHealthCheck(redis);

        // act — the test waits 1s for the timeout to fire. Acceptable in a unit-test run.
        var result = await check.CheckHealthAsync(new HealthCheckContext());

        // assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Be("Redis unreachable.");
    }

    [Fact]
    public async Task CheckHealth_OuterCancellationTokenAlreadyCancelled_ReturnsUnhealthy()
    {
        // arrange — caller cancelled before we even started (e.g., probe shutdown). The
        // linked CTS is also-cancelled, the wait throws OperationCanceledException, we
        // surface that as Unhealthy. Pinned because the alternative — letting the
        // exception propagate — would crash the probe pipeline.
        var redis = Substitute.For<IConnectionMultiplexer>();
        var db = Substitute.For<IDatabase>();
        redis.GetDatabase().Returns(db);
        db.PingAsync().Returns(new TaskCompletionSource<TimeSpan>().Task);
        var check = new RedisHealthCheck(redis);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // act
        var result = await check.CheckHealthAsync(new HealthCheckContext(), cts.Token);

        // assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
    }
}
