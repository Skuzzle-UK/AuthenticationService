using AuthenticationService.Extensions;
using AuthenticationService.ServiceDefaults;
using AuthenticationService.Settings;
using Serilog;

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

            builder.Host.UseSerilog((hostingContext, services, configuration) => configuration
                .ReadFrom.Configuration(hostingContext.Configuration)
                .ReadFrom.Services(services)
                .Enrich.FromLogContext());

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
