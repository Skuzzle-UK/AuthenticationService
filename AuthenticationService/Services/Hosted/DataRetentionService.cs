using AuthenticationService.Settings;
using AuthenticationService.Storage;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Services.Hosted;

/// <summary>
/// Background service that enforces retention policies. Periodically prunes:
/// <list type="bullet">
///   <item><description><c>AccessRecords</c> past their TTL (security event log retention).</description></item>
///   <item><description><c>RevokedTokens</c> past their natural expiry (deny-list rows the underlying token can no longer pass lifetime validation against).</description></item>
///   <item><description><c>RefreshTokens</c> past their natural expiry (consumed or otherwise, can no longer be rotated).</description></item>
/// </list>
/// </summary>
public class DataRetentionService : BackgroundService
{
    private readonly ILogger<DataRetentionService> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly DataRetentionSettings _settings;
    private readonly PeriodicTimer _periodicTimer;

    public DataRetentionService(
        ILogger<DataRetentionService> logger,
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
            "Data retention service started with cleanup interval of {Interval} hours and access record TTL of {TTL} days.",
            _settings.CleanupIntervalInHours,
            _settings.AccessRecordsTTLInDays);

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
            // Expected during shutdown, no action needed.
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

    private async Task RunCleanupAsync(CancellationToken stoppingToken)
    {
        using var scope = _serviceScopeFactory.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        context.AccessRecords.RemoveRange(context.AccessRecords.Where(x => x.CreatedAt.AddDays(_settings.AccessRecordsTTLInDays) < DateTime.UtcNow));
        context.RevokedTokens.RemoveRange(context.RevokedTokens.Where(x => x.ExpiresAt < DateTime.UtcNow));
        context.RefreshTokens.RemoveRange(context.RefreshTokens.Where(x => x.ExpiresAt < DateTime.UtcNow));

        await context.SaveChangesAsync(stoppingToken);
    }
}
