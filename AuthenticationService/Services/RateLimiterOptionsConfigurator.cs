using AuthenticationService.Constants;
using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using RedisRateLimiting;
using StackExchange.Redis;
using System.Threading.RateLimiting;

namespace AuthenticationService.Services;

/// <summary>
/// Configures the rate limiter with a Redis-backed primary plus an in-memory fallback.
/// </summary>
public sealed class RateLimiterOptionsConfigurator : IConfigureOptions<RateLimiterOptions>
{
    private readonly IConnectionMultiplexer _redis;

    public RateLimiterOptionsConfigurator(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }

    public void Configure(RateLimiterOptions options)
    {
        // Global limiter is the catch-all default applied to every request. Chained:
        // Redis primary (distributed, accurate cluster-wide cap) + in-memory fallback
        // (per-replica, kicks in if Redis is unavailable). Most-restrictive wins.
        options.GlobalLimiter = PartitionedRateLimiter.CreateChained(
            BuildRedisGlobalLimiter(),
            BuildInMemoryGlobalFallbackLimiter());

        // Strict per-IP cap for unauthenticated credential / link endpoints.
        options.AddPolicy(RateLimitPolicies.AuthStrict, context =>
        {
            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
            return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                partitionKey: $"auth-strict:{ip}",
                factory: _ => new RedisFixedWindowRateLimiterOptions
                {
                    ConnectionMultiplexerFactory = () => _redis,
                    PermitLimit = 10,
                    Window = TimeSpan.FromMinutes(1),
                });
        });

        // Per-user cap for authenticated state-changing endpoints.
        options.AddPolicy(RateLimitPolicies.AuthSensitive, context =>
        {
            var key = context.User?.FindFirst(ClaimConstants.Sub)?.Value
                      ?? context.Connection.RemoteIpAddress?.ToString()
                      ?? "anonymous";
            return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                partitionKey: $"auth-sensitive:{key}",
                factory: _ => new RedisFixedWindowRateLimiterOptions
                {
                    ConnectionMultiplexerFactory = () => _redis,
                    PermitLimit = 10,
                    Window = TimeSpan.FromMinutes(1),
                });
        });

        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    }

    private PartitionedRateLimiter<HttpContext> BuildRedisGlobalLimiter() =>
        PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            // Health-check endpoints get a permissive bucket so orchestrator / monitoring
            // probes aren't throttled alongside regular API traffic.
            if (context.Request.Path.StartsWithSegments("/healthz")
                || context.Request.Path.StartsWithSegments("/readyz"))
            {
                var probeIp = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                    partitionKey: $"health:{probeIp}",
                    factory: _ => new RedisFixedWindowRateLimiterOptions
                    {
                        ConnectionMultiplexerFactory = () => _redis,
                        PermitLimit = 30,
                        Window = TimeSpan.FromSeconds(10),
                    });
            }

            // Discovery + JWKS endpoints get their own bucket. During a key
            // rotation a fleet of consumers behind the same corporate NAT may all refresh
            // their cached JWKS within a few seconds — the default 4/10s would trip on
            // anything more than a handful.
            if (context.Request.Path.StartsWithSegments($"/{WellKnownPaths.Prefix}"))
            {
                var probeIp = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                    partitionKey: $"well-known:{probeIp}",
                    factory: _ => new RedisFixedWindowRateLimiterOptions
                    {
                        ConnectionMultiplexerFactory = () => _redis,
                        PermitLimit = 60,
                        Window = TimeSpan.FromSeconds(10),
                    });
            }

            // Default: per-user once authenticated, per-IP otherwise.
            var userId = context.User?.FindFirst(ClaimConstants.Sub)?.Value
                         ?? context.Connection.RemoteIpAddress?.ToString()
                         ?? "anonymous";

            return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                partitionKey: $"global:{userId}",
                factory: _ => new RedisFixedWindowRateLimiterOptions
                {
                    ConnectionMultiplexerFactory = () => _redis,
                    PermitLimit = 4,
                    Window = TimeSpan.FromSeconds(10),
                });
        });

    private static PartitionedRateLimiter<HttpContext> BuildInMemoryGlobalFallbackLimiter() =>
        PartitionedRateLimiter.Create<HttpContext, string>(context =>
        {
            // Same partition shape as the Redis primary so caps match meaning. Caps
            // themselves are PER-REPLICA when this is the binding constraint — i.e.
            // when Redis is down. Set roughly equal to the Redis caps, accepting that
            // with N replicas the cluster-wide effective cap during a Redis outage is
            // N× the Redis cap. Acceptable degraded mode.
            if (context.Request.Path.StartsWithSegments("/healthz")
                || context.Request.Path.StartsWithSegments("/readyz"))
            {
                var probeIp = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"health-fallback:{probeIp}",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        Window = TimeSpan.FromSeconds(10),
                        PermitLimit = 30,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0,
                    });
            }

            if (context.Request.Path.StartsWithSegments($"/{WellKnownPaths.Prefix}"))
            {
                var probeIp = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"well-known-fallback:{probeIp}",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        Window = TimeSpan.FromSeconds(10),
                        PermitLimit = 60,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0,
                    });
            }

            var userId = context.User?.FindFirst(ClaimConstants.Sub)?.Value
                         ?? context.Connection.RemoteIpAddress?.ToString()
                         ?? "anonymous";

            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: $"global-fallback:{userId}",
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    Window = TimeSpan.FromSeconds(10),
                    PermitLimit = 4,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 2,
                });
        });
}
