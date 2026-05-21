using AuthenticationService.Extensions;
using AuthenticationService.Logging;
using AuthenticationService.ServiceDefaults;
using AuthenticationService.Settings;
using AuthenticationService.Storage.Seed;
using Serilog;
using Serilog.Sinks.OpenTelemetry;

namespace AuthenticationService;

public class Program
{
    private const string ResetAdminCommand = "reset-admin";

    public static async Task Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console()
            .CreateBootstrapLogger();

        try
        {
            // Break-glass CLI: build the DI graph + run admin recovery, then exit.
            // No web pipeline starts. See docs/operations/admin-recovery.md.
            if (args.Length > 0 && string.Equals(args[0], ResetAdminCommand, StringComparison.OrdinalIgnoreCase))
            {
                Log.Information("Running admin recovery (reset-admin). Web pipeline will not start.");
                await RunResetAdminAsync(args);
                return;
            }

            Log.Information("Starting authentication service.");

            var builder = WebApplication.CreateBuilder(args);

            builder.AddServiceDefaults();

            builder.Configuration
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();

            // Cap body size — Kestrel's 30 MB default is a needless DoS surface for an
            // auth API. Tuned via HostingSettings:MaxRequestBodySizeInKilobytes.
            var hostingSettings = builder.Configuration
                .GetSection(nameof(HostingSettings))
                .Get<HostingSettings>() ?? new HostingSettings();

            builder.WebHost.ConfigureKestrel(opt =>
            {
                opt.Limits.MaxRequestBodySize = (long)hostingSettings.MaxRequestBodySizeInKilobytes * 1024;
            });

            builder.Host.UseSerilog((hostingContext, services, configuration) =>
            {
                configuration
                    .ReadFrom.Configuration(hostingContext.Configuration)
                    .ReadFrom.Services(services)
                    .Enrich.FromLogContext();

                // Without the env var, Serilog stays console-only — logs don't flow to Loki
                // and the trace<->log correlation in Grafana/Tempo breaks.
                var otlpEndpoint = hostingContext.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
                if (!string.IsNullOrWhiteSpace(otlpEndpoint))
                {
                    configuration.WriteTo.OpenTelemetry(opt =>
                    {
                        opt.Endpoint = otlpEndpoint;
                        opt.Protocol = OtlpProtocol.Grpc;
                        opt.ResourceAttributes = new Dictionary<string, object>
                        {
                            ["service.name"] = hostingContext.Configuration["OTEL_SERVICE_NAME"]
                                ?? "auth"
                        };
                    });
                }

                // Persists SecurityEventIds-tagged events to the audit table. Other events
                // pass through unchanged. See SecurityEventSink for details.
                var scopeFactory = services.GetRequiredService<IServiceScopeFactory>();
                configuration.WriteTo.Sink(new SecurityEventSink(scopeFactory));
            });

            builder.Host.ConfigureHost();

            var app = builder.Build();

            await app.ConfigureApplicationAsync();
            await app.RunAsync();
        }
        catch (Exception ex) when (ex is not HostAbortedException)
        {
            Log.Fatal(ex, "Authentication service terminated unexpectedly.");
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }

    // Reuses the same builder + DI graph as the web app so config (connection strings,
    // password policy, ResetOnStartup, etc.) is identical. We build the app but don't
    // call ConfigureApplicationAsync (no migrations, no seeder auto-run, no pipeline)
    // and don't call RunAsync — so no Kestrel, no hosted services, just DI + the reset.
    private static async Task RunResetAdminAsync(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.AddServiceDefaults();

        builder.Configuration
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
            .AddEnvironmentVariables();

        builder.Host.UseSerilog((ctx, services, cfg) => cfg
            .ReadFrom.Configuration(ctx.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext());

        builder.Host.ConfigureHost();

        var app = builder.Build();
        await app.ResetAdministratorAccountAsync();
    }
}
