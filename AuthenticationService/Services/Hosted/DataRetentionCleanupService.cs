using AuthenticationService.Settings;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Services.Hosted;

/// <summary>
/// Background sweep that deletes old rows so the database doesn't grow forever. Runs on a
/// timer (interval is configurable) and prunes:
/// <list type="bullet">
///   <item><description><c>RevokedTokenAccessAttempts</c> older than the configured retention window.</description></item>
///   <item><description><c>RevokedTokens</c> whose underlying token would already have expired naturally — keeping them on the deny-list past that point adds no value.</description></item>
///   <item><description><c>RefreshTokens</c> whose expiry has passed — they couldn't be used to refresh anyway.</description></item>
/// </list>
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

    /// <summary>
    /// One pass of cleanup. Exposed as <c>internal</c> so tests can drive the cleanup
    /// logic directly without going through <see cref="ExecuteAsync"/>'s timer loop.
    /// </summary>
    internal async Task RunCleanupAsync(CancellationToken stoppingToken)
    {
        using var scope = _serviceScopeFactory.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        var now = DateTime.UtcNow;

        // Using ExecuteDeleteAsync for efficient server-side deletes without loading entities into memory.
        await context.RevokedTokenAccessAttempts
            .Where(x => x.CreatedAt.AddDays(_settings.RevokedReplayTTLInDays) < now)
            .ExecuteDeleteAsync(stoppingToken);

        await context.RevokedTokens
            .Where(x => x.ExpiresAt < now)
            .ExecuteDeleteAsync(stoppingToken);

        await context.RefreshTokens
            .Where(x => x.ExpiresAt < now)
            .ExecuteDeleteAsync(stoppingToken);
    }
}
