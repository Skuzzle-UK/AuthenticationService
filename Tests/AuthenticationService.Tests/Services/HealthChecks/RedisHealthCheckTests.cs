using AuthenticationService.Services.HealthChecks;
using AwesomeAssertions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using NSubstitute;
using StackExchange.Redis;

namespace AuthenticationService.Tests.Services.HealthChecks;

/// <summary>
/// Wraps <c>PingAsync</c> with a 1-second timeout. Three paths: success, throw, hang-until-timeout.
/// </summary>
public class RedisHealthCheckTests
{
    [Fact]
    public async Task CheckHealth_PingSucceeds_ReturnsHealthy()
    {
        // arrange
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
        // arrange — connection refused etc.; surface as Unhealthy so K8s readiness pulls the pod from rotation.
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
        // arrange — 1-second timeout via linked CTS turns the wait into TaskCanceledException → Unhealthy.
        var redis = Substitute.For<IConnectionMultiplexer>();
        var db = Substitute.For<IDatabase>();
        redis.GetDatabase().Returns(db);
        var hangingTask = new TaskCompletionSource<TimeSpan>().Task;
        db.PingAsync().Returns(hangingTask);
        var check = new RedisHealthCheck(redis);

        // act — test waits 1s for the timeout to fire.
        var result = await check.CheckHealthAsync(new HealthCheckContext());

        // assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Be("Redis unreachable.");
    }

    [Fact]
    public async Task CheckHealth_OuterCancellationTokenAlreadyCancelled_ReturnsUnhealthy()
    {
        // arrange — already-cancelled outer token must surface as Unhealthy; letting the exception propagate would crash the probe pipeline.
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
