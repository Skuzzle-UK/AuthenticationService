
using AuthenticationService.Storage;

namespace AuthenticationService.Services.Hosted;

public class RevokedTokenCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _serviceScopeFactory;

    public RevokedTokenCleanupService(IServiceScopeFactory serviceScopeFactory)
    {
        _serviceScopeFactory = serviceScopeFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            using var scope = _serviceScopeFactory.CreateScope();
            {
                var context = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
                // TODO: Needs configuration values for the cleanup interval and the retention period /nb
                context.AccessRecords.RemoveRange(context.AccessRecords.Where(x => x.AccessAt.AddYears(5) < DateTime.UtcNow));
                context.RevokedTokens.RemoveRange(context.RevokedTokens.Where(x => x.ExpiresAt < DateTime.UtcNow));

                await context.SaveChangesAsync(stoppingToken);
            }
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }
}
