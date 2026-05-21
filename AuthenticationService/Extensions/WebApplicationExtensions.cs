using AuthenticationService.Middleware;
using AuthenticationService.Settings;
using AuthenticationService.Storage;
using AuthenticationService.Storage.Seed;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Serilog;

namespace AuthenticationService.Extensions;

/// <summary>
/// Builds the HTTP request pipeline. Companion to <see cref="HostExtensions"/> which
/// registers the services.
/// </summary>
public static class WebApplicationExtensions
{
    public static async Task<WebApplication> ConfigureApplicationAsync(this WebApplication app)
    {
        // Must run first — anything downstream that reads RemoteIpAddress (auth audit,
        // rate-limit partitioning) will see the proxy IP instead of the real client
        // without this.
        app.UseForwardedHeaders();

        app.UseSerilogRequestLogging(options =>
        {
            options.GetLevel = (httpContext, elapsed, ex) =>
                httpContext.Request.Path.StartsWithSegments("/livez")
                || httpContext.Request.Path.StartsWithSegments("/readyz")
                || httpContext.Request.Path.StartsWithSegments("/healthz")
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

        // Gated off in integration tests — AppHost on Linux CI can't reliably bind HTTPS.
        var hostingSettings = app.Services.GetRequiredService<IOptions<HostingSettings>>().Value;
        if (hostingSettings.HttpsRedirectionEnabled)
        {
            app.UseHttpsRedirection();
        }
        app.UseStaticFiles();
        app.UseMiddleware<SecurityHeadersMiddleware>();

        // Must run before UseAuthentication
        app.UseCors();

        app.UseApplicationMiddleware();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRateLimiter();
        app.UseHealthChecks();
        app.MapControllers();
        app.MapRazorPages();

        return app;
    }

    private static void UseHealthChecks(this WebApplication app)
    {
        // K8s restarts the pod if this fails.
        app.MapHealthChecks("/livez", new HealthCheckOptions
        {
            Predicate = check => check.Tags.Contains("live")
        }).AllowAnonymous();

        // K8s pulls the pod from service routing (but doesn't restart) if this fails.
        app.MapHealthChecks("/readyz", new HealthCheckOptions
        {
            Predicate = check => check.Tags.Contains("ready")
        }).AllowAnonymous();

        //Blanket "everything" endpoint for ops debugging.
        app.MapHealthChecks("/healthz").AllowAnonymous();
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
