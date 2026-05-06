using AuthenticationService.Middleware;
using AuthenticationService.Storage;
using AuthenticationService.Storage.Seed;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace AuthenticationService.Extensions;

/// <summary>
/// Builds the HTTP request pipeline. The companion to <see cref="HostExtensions"/> —
/// services are registered there, the pipeline is wired up here.
/// </summary>
public static class WebApplicationExtensions
{
    /// <summary>
    /// Wires up the full request pipeline: forwarded headers, request logging, Swagger,
    /// (optional) startup migrations + seed, HTTPS, CORS, auth, custom middleware, the
    /// rate limiter, health-check endpoints, and finally controllers + Razor pages.
    /// Order matters — each step has a comment where it's not obvious.
    /// </summary>
    public static async Task<WebApplication> ConfigureApplicationAsync(this WebApplication app)
    {
        // Always keep UseForwardedHeaders at the top of the pipeline, before any middleware that might consume the forwarded header values (e.g. auth, rate-limiting).
        // Without this, the service won't respect X-Forwarded-For and all client IPs will be the load balancers — meaning audit logs and the rate-limiter's per-IP partitioning will both be wrong.
        app.UseForwardedHeaders();

        app.UseSerilogRequestLogging(options =>
        {
            options.GetLevel = (httpContext, elapsed, ex) =>
                httpContext.Request.Path.StartsWithSegments("/healthz")
                || httpContext.Request.Path.StartsWithSegments("/readyz")
                    ? Serilog.Events.LogEventLevel.Verbose
                    : Serilog.Events.LogEventLevel.Information;
        });

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

        await app.RuntimeDbSeedAsync();

        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        // Must run before UseAuthentication
        app.UseCors();

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

    private static WebApplication UseApplicationMiddleware(this WebApplication app)
    {
        app.UseMiddleware<RevokedTokenMiddleware>();
        return app;
    }

    private static WebApplication RunMigrations(this WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
            dbContext.Database.Migrate();
        }

        return app;
    }
}
