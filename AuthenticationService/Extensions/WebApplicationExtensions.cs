using AuthenticationService.Middleware;
using AuthenticationService.Storage;
using AuthenticationService.Storage.Seed;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Extensions;

public static class WebApplicationExtensions
{
    public static WebApplication ConfigureApplication(this WebApplication app)
    {
        // Always keep UseForwardedHeaders at the top of the pipeline, before any middleware that might consume the forwarded header values (e.g. auth, rate-limiting).
        // Without this, the service won't respect X-Forwarded-For and all client IPs will be the load balancers — meaning audit logs and the rate-limiter's per-IP partitioning will both be wrong.
        app.UseForwardedHeaders();

        app.UseSwagger();
        app.UseSwaggerUI(opt =>
        {
            opt.SwaggerEndpoint("/swagger/v1/swagger.json", "Authentication API V1");
        });

        if (app.Configuration.GetValue("RunMigrationsAtStartup", defaultValue: true))
        {
            app.RunMigrations();
        }
        else
        {
            app.Logger.LogInformation(
                "Skipping startup migrations (RunMigrationsAtStartup=false). " +
                "Ensure migrations are applied via the deploy pipeline before this replica serves traffic.");
        }

        app.RuntimeDbSeed();

        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseApplicationMiddleware();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRateLimiter();

        // Health-check endpoints. Anonymous (orchestrators don't carry credentials), but
        // still rate-limited via the path-based partition in AddRateLimiting — generous
        // enough for orchestrator probes, tight enough to cap DDoS abuse.
        app.MapHealthChecks("/healthz", new HealthCheckOptions
        {
            Predicate = check => check.Tags.Contains("live")
        }).AllowAnonymous();

        app.MapHealthChecks("/readyz", new HealthCheckOptions
        {
            Predicate = check => check.Tags.Contains("ready")
        }).AllowAnonymous();

        app.MapControllers();
        app.MapRazorPages();

        return app;
    }

    public static WebApplication UseApplicationMiddleware(this WebApplication app)
    {
        app.UseMiddleware<RevokedTokenMiddleware>();
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
