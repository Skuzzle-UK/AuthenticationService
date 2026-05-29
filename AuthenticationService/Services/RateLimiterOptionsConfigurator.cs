using AuthenticationService.Constants;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Extensions;
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
    private const string RedisKeyPrefix = "AuthenticationService:RateLimit:";

    private readonly IConnectionMultiplexer _redis;
    private readonly HostingSettings _hostingSettings;

    public RateLimiterOptionsConfigurator(
        IConnectionMultiplexer redis,
        IOptions<HostingSettings> hostingSettings)
    {
        _redis = redis;
        _hostingSettings = hostingSettings.Value;
    }

    public void Configure(RateLimiterOptions options)
    {
        if (!_hostingSettings.RateLimitingEnabled)
        {
            // Integration-test escape hatch: no-op limiters across the board. Named policies
            // still register so [EnableRateLimiting] endpoints don't 500 on an unknown name.
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
                _ => RateLimitPartition.GetNoLimiter("disabled"));
            options.AddPolicy(RateLimitPolicies.AuthStrict, _ => RateLimitPartition.GetNoLimiter("disabled"));
            options.AddPolicy(RateLimitPolicies.AuthSensitive, _ => RateLimitPartition.GetNoLimiter("disabled"));
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            return;
        }

        // Redis primary (cluster-wide cap) chained with in-memory fallback (per-replica,
        // for Redis outages). Most-restrictive wins.
        options.GlobalLimiter = PartitionedRateLimiter.CreateChained(
            BuildRedisGlobalLimiter(),
            BuildInMemoryGlobalFallbackLimiter());

        // Strict per-IP cap for unauthenticated credential / link endpoints.
        options.AddPolicy(RateLimitPolicies.AuthStrict, context =>
        {
            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
            return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                partitionKey: $"{RedisKeyPrefix}auth-strict:{ip}",
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
            var key = context.User?.GetUserId()
                      ?? context.Connection.RemoteIpAddress?.ToString()
                      ?? "anonymous";
            return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                partitionKey: $"{RedisKeyPrefix}auth-sensitive:{key}",
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
            // Permissive bucket for orchestrator/monitoring probes.
            if (context.Request.Path.StartsWithSegments("/livez")
                || context.Request.Path.StartsWithSegments("/readyz")
                || context.Request.Path.StartsWithSegments("/healthz"))
            {
                var probeIp = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                    partitionKey: $"{RedisKeyPrefix}health:{probeIp}",
                    factory: _ => new RedisFixedWindowRateLimiterOptions
                    {
                        ConnectionMultiplexerFactory = () => _redis,
                        PermitLimit = 30,
                        Window = TimeSpan.FromSeconds(10),
                    });
            }

            // Discovery + JWKS need headroom: during key rotation, many consumers behind one
            // NAT may all refresh within seconds — the default 4/10s would trip on a handful.
            if (context.Request.Path.StartsWithSegments($"/{WellKnownPaths.Prefix}"))
            {
                var probeIp = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                    partitionKey: $"{RedisKeyPrefix}well-known:{probeIp}",
                    factory: _ => new RedisFixedWindowRateLimiterOptions
                    {
                        ConnectionMultiplexerFactory = () => _redis,
                        PermitLimit = 60,
                        Window = TimeSpan.FromSeconds(10),
                    });
            }

            // Default: per-user once authenticated, per-IP otherwise.
            var userId = context.User?.GetUserId()
                         ?? context.Connection.RemoteIpAddress?.ToString()
                         ?? "anonymous";

            return RedisRateLimitPartition.GetFixedWindowRateLimiter(
                partitionKey: $"{RedisKeyPrefix}global:{userId}",
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
            // Mirrors the Redis primary's partition shape. Caps are PER-REPLICA when Redis
            // is down — cluster-wide effective cap is N× the Redis cap. Acceptable degraded mode.
            if (context.Request.Path.StartsWithSegments("/livez")
                || context.Request.Path.StartsWithSegments("/readyz")
                || context.Request.Path.StartsWithSegments("/healthz"))
            {
                var probeIp = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: $"{RedisKeyPrefix}health-fallback:{probeIp}",
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
                    partitionKey: $"{RedisKeyPrefix}well-known-fallback:{probeIp}",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        Window = TimeSpan.FromSeconds(10),
                        PermitLimit = 60,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0,
                    });
            }

            var userId = context.User?.GetUserId()
                         ?? context.Connection.RemoteIpAddress?.ToString()
                         ?? "anonymous";

            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: $"{RedisKeyPrefix}global-fallback:{userId}",
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    Window = TimeSpan.FromSeconds(10),
                    PermitLimit = 4,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 2,
                });
        });
}
