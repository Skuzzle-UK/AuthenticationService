using AuthenticationService.Observability;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Services.Hosted;

/// <summary>
/// Periodically refreshes the snapshot values that back <see cref="AuthMetrics"/>'s
/// observable user gauges (<c>auth.users.total</c>, <c>auth.users.mfa_enabled.total</c>,
/// <c>auth.users.locked.total</c>).
///
/// <para>Observable gauges report a current-state value, not a delta — so they need
/// someone to compute that value somewhere. Doing the query inline from the gauge
/// callback would tie DB load to scrape frequency; this service decouples them by
/// caching the latest snapshot.</para>
///
/// <para>Gated by <c>HostingSettings:BackgroundWorkersEnabled</c> (registered in
/// <c>HostExtensions.AddHostedServices</c>) so only the worker pod queries — every
/// replica would return the same global count from the same DB.</para>
/// </summary>
public class UserGaugeRefreshService : BackgroundService
{
    /// <summary>
    /// Refresh interval. Hardcoded at 60s — gauge values are not latency-sensitive
    /// and three EF Count queries per minute is invisible against any realistic
    /// database load. Promote to a setting if a use case ever needs it tunable.
    /// </summary>
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
            // Refresh once up front so gauges aren't zero until the first tick.
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

    /// <summary>
    /// One refresh pass. Internal so tests can drive it without going through the timer.
    /// </summary>
    internal async Task RefreshAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var scope = _serviceScopeFactory.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<DatabaseContext>();

            var now = DateTimeOffset.UtcNow;

            // Three count queries. Cheap — Users table is small and these are
            // index-friendly predicates.
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
            // Don't tear down the timer loop on a transient DB error — log and try
            // again next tick. The previous gauge values stay cached until the next
            // successful refresh.
            _logger.LogWarning(
                ex,
                "User-gauge refresh failed: {ErrorMsg}. Will retry on next tick.",
                ex.Message);
        }
    }
}
