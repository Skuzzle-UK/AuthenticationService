using AuthenticationService.Storage;
using AuthenticationService.Storage.Seed;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Extensions;

public static class WebApplicationExtensions
{
    public static WebApplication ConfigureApplication(this WebApplication app)
    {
        app.RunMigrations();
        app.RuntimeDbSeed();
        app.UseHttpsRedirection();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRateLimiter();
        app.MapControllers();
        return app;
    }

    public static WebApplication RunMigrations(this WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
            dbContext.Database.Migrate();
        }

        return app;
    }
}
