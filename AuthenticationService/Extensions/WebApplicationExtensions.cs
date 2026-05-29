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
            // Parameterless overload + AddProblemDetails() in HostExtensions yields
            // RFC 7807 JSON on unhandled exceptions. Dev keeps the DeveloperExceptionPage.
            app.UseExceptionHandler();
            app.UseHsts();
        }

        // Format empty 4xx/5xx responses (e.g. a 404 with no body) as ProblemDetails too.
        app.UseStatusCodePages();

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
        // Multi-tenancy Phase 1: registered after JwtBearer auth so the principal
        // exists. Reads `tid` claim if present, populates ITenantAccessor. No-op when
        // unauthenticated or when the token doesn't carry tid (Phase 1 tokens don't —
        // Phase 3 wires that in at issuance time).
        app.UseMiddleware<TenantResolutionMiddleware>();
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
