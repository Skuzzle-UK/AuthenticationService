using AuthenticationService.Settings;
using AuthenticationService.Storage;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Services.Hosted;

public class RevokedTokenCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly RevokedTokenSettings _settings;

    public RevokedTokenCleanupService(
        IServiceScopeFactory serviceScopeFactory,
        IOptions<RevokedTokenSettings> settings)
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
                context.AccessRecords.RemoveRange(context.AccessRecords.Where(x => x.AccessAt.AddDays(_settings.AccessRecordsTTLInDays) < DateTime.UtcNow));
                context.RevokedTokens.RemoveRange(context.RevokedTokens.Where(x => x.ExpiresAt < DateTime.UtcNow));

                await context.SaveChangesAsync(stoppingToken);
            }
            await Task.Delay(TimeSpan.FromMinutes(_settings.CleanupIntervalInMinutes), stoppingToken);
        }
    }
}
