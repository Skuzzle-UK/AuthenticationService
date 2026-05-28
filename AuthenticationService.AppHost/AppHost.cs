using AuthenticationService.AppHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

var builder = DistributedApplication.CreateBuilder(args);

// Dev-mode flags: --integration-test forces HTTP-only (Linux CI dev-cert workaround);
// --rate-limiting-disabled turns the limiter into a no-op for multi-scenario runs;
// --with-backstage opts into the Backstage container (image must be built locally).
var integrationTestMode = args.Contains("--integration-test");
var rateLimitingDisabled = args.Contains("--rate-limiting-disabled");
var withBackstage = args.Contains("--with-backstage");

// Database provider selection: --db-provider=<name> arg, else INTEGRATION_DB_PROVIDER
// env var, else MySQL. Matches DatabaseProviders constants in the main project.
var dbProvider = args
    .FirstOrDefault(a => a.StartsWith("--db-provider=", StringComparison.OrdinalIgnoreCase))
    ?["--db-provider=".Length..]
    ?? Environment.GetEnvironmentVariable("INTEGRATION_DB_PROVIDER");
if (string.IsNullOrWhiteSpace(dbProvider))
{
    dbProvider = "MySQL";
}

var smtp = builder.AddContainer("smtp4dev", "rnwood/smtp4dev")
    .WithEndpoint(name: "smtp", targetPort: 25)
    .WithHttpEndpoint(name: "http", targetPort: 80);

// Each AddDatabase returns a provider-specific resource builder, but they all implement
// IResourceWithConnectionString (IResourceBuilder<out T> is covariant) so the unified
// reference works downstream.
IResourceBuilder<IResourceWithConnectionString> authDb = dbProvider switch
{
    "MySQL" => builder.AddMySql("mysql").AddDatabase("AuthenticationService"),
    "SqlServer" => builder.AddSqlServer("sqlserver").AddDatabase("AuthenticationService"),
    "PostgreSQL" => builder.AddPostgres("postgres").AddDatabase("AuthenticationService"),
    _ => throw new InvalidOperationException(
        $"Unknown DB provider '{dbProvider}'. Supported: MySQL, SqlServer, PostgreSQL. "
        + "Set --db-provider=<name> or INTEGRATION_DB_PROVIDER env var.")
};

var redis = builder.AddRedis("redis")
    .WithRedisInsight();

// grafana/otel-lgtm bundles Grafana + Tempo + Loki + Prometheus. Skipped in test mode —
// ServiceDefaults gates the OTLP exporter on OTEL_EXPORTER_OTLP_ENDPOINT, so leaving
// the env var unset cleanly disables export.
IResourceBuilder<ContainerResource>? lgtm = null;
if (!integrationTestMode)
{
    lgtm = builder.AddContainer("grafana", "grafana/otel-lgtm")
        .WithEndpoint(name: "grafana-ui", targetPort: 3000, port: 3000, scheme: "http")
        // scheme: "http" is load-bearing — Grpc.Net.Client only resolves http/https/dns,
        // so the default tcp:// scheme throws "No address resolver configured".
        .WithEndpoint(name: "otlp-grpc", targetPort: 4317, scheme: "http")
        .WithEndpoint(name: "otlp-http", targetPort: 4318, scheme: "http");

    // HTTP-API import instead of file-based provisioning — Docker Desktop on Windows
    // rejects single-file bind mounts with "mount path must be absolute".
    var appHostRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
    var dashboardPath = Path.Combine(appHostRoot, "grafana", "dashboards", "auth-overview.json");

    builder.Eventing.Subscribe<ResourceReadyEvent>(lgtm.Resource, async (evt, ct) =>
    {
        var grafanaUrl = lgtm.GetEndpoint("grafana-ui").Url;
        var logger = evt.Services.GetRequiredService<ILogger<DistributedApplication>>();
        await GrafanaDashboardProvisioner.ImportDashboardAsync(grafanaUrl, dashboardPath, logger, ct);
    });
}

var auth = builder.AddProject<Projects.AuthenticationService>("auth")
    // AppHost is dev/test-only. Forcing Development mode lets EcdsaKeyProvider
    // auto-generate a dev signing key when no PEM is present (CI runners need this).
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithEnvironment("EmailServerSettings__SmtpServer", smtp.GetEndpoint("smtp").Property(EndpointProperty.Host))
    .WithEnvironment("EmailServerSettings__Port", smtp.GetEndpoint("smtp").Property(EndpointProperty.Port))
    .WithEnvironment("EmailServerSettings__UserName", "")
    .WithEnvironment("EmailServerSettings__Password", "")
    .WithEnvironment("DatabaseSettings__Provider", dbProvider)
    // Connection-string env var key matches the active provider name so the auth
    // service's ConnectionStrings:{Provider} lookup resolves correctly.
    .WithEnvironment($"ConnectionStrings__{dbProvider}", authDb)
    .WithEnvironment("ConnectionStrings__Redis", redis)
    .WaitFor(authDb)
    .WaitFor(redis)
    .WaitFor(smtp);

if (lgtm is not null)
{
    // Setting OTEL_EXPORTER_OTLP_ENDPOINT flips on the exporter in ServiceDefaults.
    // No WaitFor(lgtm) — OTel queues and retries silently, blocking auth on the
    // dashboard container would be backwards.
    auth
        .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", lgtm.GetEndpoint("otlp-grpc"))
        .WithEnvironment("OTEL_SERVICE_NAME", "auth");
}

// Production-shape default; test mode overrides to the http endpoint below.
auth.WithEnvironment("PublicUrlSettings__BaseUrl", auth.GetEndpoint("https"));

if (integrationTestMode)
{
    // Linux CI runners struggle with dev certs — flip off HTTPS-gated behaviours
    // and point email links at the http transport tests are using.
    auth.WithEnvironment("HostingSettings__HttpsRedirectionEnabled", "false");
    auth.WithEnvironment("ClientCredentialsSettings__RequireHttps", "false");
    auth.WithEnvironment("PublicUrlSettings__BaseUrl", auth.GetEndpoint("http"));
}

if (rateLimitingDisabled)
{
    auth.WithEnvironment("HostingSettings__RateLimitingEnabled", "false");
}

// Backstage developer portal (opt-in). Image built locally by
// scripts/setup-local-backstage.ps1 — see docs/operations/local-backstage.md.
// Port 7007 is Backstage's convention.
if (withBackstage)
{
    // Walks up out of bin/Debug/<tfm>/ to the solution root.
    var repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));

    builder.AddContainer("backstage", "authentication-service-backstage", "local")
        .WithEndpoint(name: "backstage-ui", targetPort: 7007, port: 7007, scheme: "http")
        // Folder mount (not single-file) sidesteps Docker Desktop on Windows's
        // "mount path must be absolute" rejection. Overlay app-config is baked
        // into the image, not mounted.
        .WithBindMount(repoRoot, "/repo", isReadOnly: true);
}

builder.Build().Run();
