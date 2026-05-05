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
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly DataRetentionSettings _settings;

    public DataRetentionService(
        IServiceScopeFactory serviceScopeFactory,
        IOptions<DataRetentionSettings> settings)
    {
        _serviceScopeFactory = serviceScopeFactory;
        _settings = settings.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            using var scope = _serviceScopeFactory.CreateScope();
            {
                var context = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
                context.AccessRecords.RemoveRange(context.AccessRecords.Where(x => x.CreatedAt.AddDays(_settings.AccessRecordsTTLInDays) < DateTime.UtcNow));
                context.RevokedTokens.RemoveRange(context.RevokedTokens.Where(x => x.ExpiresAt < DateTime.UtcNow));
                context.RefreshTokens.RemoveRange(context.RefreshTokens.Where(x => x.ExpiresAt < DateTime.UtcNow));

                await context.SaveChangesAsync(stoppingToken);
            }
            await Task.Delay(TimeSpan.FromHours(_settings.CleanupIntervalInHours), stoppingToken);
        }
    }
}
