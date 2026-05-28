using AuthenticationService.Settings;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Services.Hosted;

/// <summary>
/// Background sweep that prunes expired audit and token rows so the database doesn't grow forever.
/// </summary>
public class DataRetentionCleanupService : BackgroundService
{
    private readonly ILogger<DataRetentionCleanupService> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly DataRetentionSettings _settings;
    private readonly PeriodicTimer _periodicTimer;

    public DataRetentionCleanupService(
        ILogger<DataRetentionCleanupService> logger,
        IServiceScopeFactory serviceScopeFactory,
        IOptions<DataRetentionSettings> settings)
    {
        _logger = logger;
        _serviceScopeFactory = serviceScopeFactory;
        _settings = settings.Value;

        _periodicTimer = new PeriodicTimer(TimeSpan.FromHours(_settings.CleanupIntervalInHours));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Data retention service started with cleanup interval of {Interval} hours and revoked-replay TTL of {TTL} days.",
            _settings.CleanupIntervalInHours,
            _settings.RevokedReplayTTLInDays);

        try
        {
            await RunCleanupAsync(stoppingToken);
            while (await _periodicTimer.WaitForNextTickAsync(stoppingToken))
            {
                await RunCleanupAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Data retention service cancellation requested.");
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Data retention service terminated unexpectedly with error: {ErrorMsg}.",
                ex.Message);
        }
        finally
        {
            _periodicTimer.Dispose();
            _logger.LogInformation("Data retention service stopped.");
        }
    }

    // Internal so tests can drive cleanup without the timer loop.
    internal async Task RunCleanupAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var scope = _serviceScopeFactory.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
            var now = DateTimeOffset.UtcNow;
            // Move the AddDays to the parameter side so the WHERE compares a column against
            // a literal — every provider's translator handles that, and the test SQLite
            // backend's DateTimeOffset converter only sees plain column-vs-parameter ops.
            var auditCutoff = now.AddDays(-_settings.RevokedReplayTTLInDays);
            var securityEventCutoff = now.AddDays(-_settings.SecurityEventTTLInDays);

            // ExecuteDeleteAsync — server-side delete, no entity load.
            await context.RevokedTokenAccessAttempts
                .Where(x => x.CreatedAt < auditCutoff)
                .ExecuteDeleteAsync(stoppingToken);

            await context.RevokedTokens
                .Where(x => x.ExpiresAt < now)
                .ExecuteDeleteAsync(stoppingToken);

            await context.RefreshTokens
                .Where(x => x.ExpiresAt < now)
                .ExecuteDeleteAsync(stoppingToken);

            await context.SecurityEvents
                .Where(x => x.Timestamp < securityEventCutoff)
                .ExecuteDeleteAsync(stoppingToken);
        }
        catch (Exception ex)
        {
            // Don't tear down the timer on a transient DB error — try again next interval.
            _logger.LogWarning(
                ex,
                "Data retention cleanup failed: {ErrorMsg}. Will retry on next sweep.",
                ex.Message);
        }
    }
}
