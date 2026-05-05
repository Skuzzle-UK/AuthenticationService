using Microsoft.Extensions.Diagnostics.HealthChecks;
using StackExchange.Redis;

namespace AuthenticationService.Services.HealthChecks;

/// <summary>
/// Readiness probe for Redis. Pings the multiplexer with a short timeout. Reports Healthy
/// when Redis is reachable, Unhealthy otherwise. Uses the existing
/// <see cref="IConnectionMultiplexer"/> registered for data-protection — no separate
/// connection.
/// </summary>
public class RedisHealthCheck : IHealthCheck
{
    private static readonly TimeSpan PingTimeout = TimeSpan.FromSeconds(1);

    private readonly IConnectionMultiplexer _redis;

    public RedisHealthCheck(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var db = _redis.GetDatabase();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(PingTimeout);
            await db.PingAsync().WaitAsync(cts.Token);

            return HealthCheckResult.Healthy("Redis reachable.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Redis unreachable.", ex);
        }
    }
}
