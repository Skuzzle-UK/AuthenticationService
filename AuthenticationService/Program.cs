using AuthenticationService.Extensions;
using AuthenticationService.ServiceDefaults;
using AuthenticationService.Settings;
using Serilog;
using Serilog.Sinks.OpenTelemetry;

namespace AuthenticationService;

public class Program
{
    public static async Task Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console()
            .CreateBootstrapLogger();

        try
        {
            Log.Information("Starting authentication service.");

            var builder = WebApplication.CreateBuilder(args);

            builder.AddServiceDefaults();

            builder.Configuration
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();

            // Cap inbound request body size. This is an auth service — every endpoint
            // accepts only small JSON bodies (login, registration, etc.). Kestrel's 30 MB
            // default is overkill and a small DoS surface; cap it tight via
            // HostingSettings:MaxRequestBodySizeInKilobytes (default 1024 KB / 1 MB).
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

                // Without the env var, Serilog stays console-only and logs don't flow to Loki.
                // Lets operators click from a trace span in Grafana / Tempo into the
                // log lines emitted during that request, since both share the same
                // trace_id and span_id.
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
}
