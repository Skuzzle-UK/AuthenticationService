using AuthenticationService.Observability;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Services.Hosted;

/// <summary>
/// Refreshes the cached snapshots behind <see cref="AuthMetrics"/>'s observable user gauges
/// (total, mfa_enabled, locked). Caches the values so scrape frequency doesn't drive DB load.
/// Gated by <c>HostingSettings:BackgroundWorkersEnabled</c> so only the worker pod queries.
/// </summary>
public class UserGaugeRefreshService : BackgroundService
{
    // 60s is hardcoded — gauges aren't latency-sensitive and three Count queries/min is invisible.
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(60);

    private readonly ILogger<UserGaugeRefreshService> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly AuthMetrics _metrics;

    public UserGaugeRefreshService(
        ILogger<UserGaugeRefreshService> logger,
        IServiceScopeFactory serviceScopeFactory,
        AuthMetrics metrics)
    {
        _logger = logger;
        _serviceScopeFactory = serviceScopeFactory;
        _metrics = metrics;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "User-gauge refresh service started. Sweep every {RefreshSeconds}s.",
            RefreshInterval.TotalSeconds);

        using var timer = new PeriodicTimer(RefreshInterval);

        try
        {
            // Prime gauges so they aren't zero until the first tick.
            await RefreshAsync(stoppingToken);
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await RefreshAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("User-gauge refresh service cancellation requested.");
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "User-gauge refresh service terminated unexpectedly: {ErrorMsg}",
                ex.Message);
        }
        finally
        {
            _logger.LogInformation("User-gauge refresh service stopped.");
        }
    }

    // Internal so tests can drive it without the timer loop.
    internal async Task RefreshAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var scope = _serviceScopeFactory.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<DatabaseContext>();

            var now = DateTimeOffset.UtcNow;

            var totalUsers = await context.Users.LongCountAsync(stoppingToken);
            
            var mfaEnabledUsers = await context.Users
                .Where(u => u.TwoFactorEnabled)
                .LongCountAsync(stoppingToken);
            
            var lockedUsers = await context.Users
                .Where(u => u.LockoutEnd != null && u.LockoutEnd > now)
                .LongCountAsync(stoppingToken);

            _metrics.UpdateUserGauges(totalUsers, mfaEnabledUsers, lockedUsers);
        }
        catch (Exception ex)
        {
            // Don't tear down the timer on a transient DB error — previous values stay cached.
            _logger.LogWarning(
                ex,
                "User-gauge refresh failed: {ErrorMsg}. Will retry on next tick.",
                ex.Message);
        }
    }
}
