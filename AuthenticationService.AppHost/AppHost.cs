using AuthenticationService.AppHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

var builder = DistributedApplication.CreateBuilder(args);

// Three independent dev-mode flags:
//
//   --integration-test         Transport: forces HTTP-only operation (HTTPS redirect
//                              off, PublicUrlSettings:BaseUrl points at the http
//                              endpoint). Avoids the Linux-CI dev-cert dance.
//                              Every integration-test fixture passes this.
//
//   --rate-limiting-disabled   Behaviour: turns the rate limiter into a no-op so a
//                              sequence of credential calls across scenarios doesn't
//                              trip the global 4/10s cap. The dedicated rate-limiter
//                              integration test specifically does NOT pass this so it
//                              can exercise the real limiter.
//
//   --with-backstage           Adds a Backstage container to the AppHost graph so devs
//                              can preview the catalog + TechDocs locally. Opt-in
//                              because (a) Backstage adds ~30s to AppHost startup,
//                              (b) the container image isn't published by default
//                              (the team builds + tags their own — see
//                              docs/operations/local-backstage.md). Default F5
//                              behaviour without this flag is unchanged.
//
// Real F5 (without flags) passes none, so dev / prod behaviour is identical to a plain run.
var integrationTestMode = args.Contains("--integration-test");
var rateLimitingDisabled = args.Contains("--rate-limiting-disabled");
var withBackstage = args.Contains("--with-backstage");

var smtp = builder.AddContainer("smtp4dev", "rnwood/smtp4dev")
    .WithEndpoint(name: "smtp", targetPort: 25)
    .WithHttpEndpoint(name: "http", targetPort: 80);

var mysql = builder.AddMySql("mysql");
var authDb = mysql.AddDatabase("AuthenticationService");

var redis = builder.AddRedis("redis")
    .WithRedisInsight();

// Local observability stack — grafana/otel-lgtm bundles Grafana + Tempo (traces) +
// Loki (logs) + Prometheus (metrics) in one container. Receives OTLP on 4317 (gRPC)
// and 4318 (HTTP); Grafana UI is on 3000 with datasources preconfigured. Skipped
// under --integration-test because (a) tests don't care about telemetry and (b) the
// extra container slows down test boot. The auth service won't emit anywhere when
// OTEL_EXPORTER_OTLP_ENDPOINT is unset (ServiceDefaults gates the exporter on it),
// so leaving the env var off in test mode cleanly disables export.
IResourceBuilder<ContainerResource>? lgtm = null;
if (!integrationTestMode)
{
    lgtm = builder.AddContainer("grafana", "grafana/otel-lgtm")
        .WithEndpoint(name: "grafana-ui", targetPort: 3000, port: 3000, scheme: "http")
        // scheme: "http" is load-bearing — OTLP gRPC is HTTP/2 over TCP, and the
        // .NET Grpc.Net.Client (used by Serilog's OTLP sink) only resolves http://,
        // https://, and dns:// schemes. Default-scheme tcp:// from WithEndpoint
        // throws "No address resolver configured for the scheme 'tcp'."
        .WithEndpoint(name: "otlp-grpc", targetPort: 4317, scheme: "http")
        .WithEndpoint(name: "otlp-http", targetPort: 4318, scheme: "http");

    // Auto-import the "Auth Service Overview" dashboard via Grafana's HTTP API once
    // the container reports ready. File-based provisioning (bind-mount of the JSON)
    // works on Linux but Docker Desktop on Windows rejects single-file bind mounts
    // with "mount path must be absolute"; the HTTP-API route side-steps that.
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
    // Force the auth project into Development mode whenever it runs under the AppHost.
    // The AppHost is dev/test-only (production deploys don't ship it), and several auth
    // service behaviours gate on Environment.IsDevelopment() — most importantly,
    // EcdsaKeyProvider auto-generates a dev signing key when there's no PEM in the
    // configured key directory. Without this env var, CI runners (where ASPNETCORE_ENVIRONMENT
    // isn't set elsewhere) would fail to start the auth project because there's no key
    // to sign with.
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithEnvironment("EmailServerSettings__SmtpServer", smtp.GetEndpoint("smtp").Property(EndpointProperty.Host))
    .WithEnvironment("EmailServerSettings__Port", smtp.GetEndpoint("smtp").Property(EndpointProperty.Port))
    .WithEnvironment("EmailServerSettings__UserName", "")
    .WithEnvironment("EmailServerSettings__Password", "")
    .WithEnvironment("ConnectionStrings__MySQL", authDb)
    .WithEnvironment("ConnectionStrings__Redis", redis)
    .WaitFor(authDb)
    .WaitFor(redis)
    .WaitFor(smtp);

if (lgtm is not null)
{
    // ServiceDefaults' ConfigureOpenTelemetry gates the OTLP exporter on this env var
    // being set — so configuring it here flips the exporter on. Point at the gRPC
    // endpoint (the .NET OTel SDK defaults to gRPC, no need to set _PROTOCOL).
    //
    // Deliberately NOT WaitFor(lgtm) — telemetry is fire-and-forget; if Grafana takes
    // a few seconds longer to start than auth, the OTel SDK queues + retries failed
    // exports silently. Blocking auth start on the dashboard container would be
    // backwards.
    auth
        .WithEnvironment("OTEL_EXPORTER_OTLP_ENDPOINT", lgtm.GetEndpoint("otlp-grpc"))
        .WithEnvironment("OTEL_SERVICE_NAME", "auth");
}

// Default: BaseUrl points at the https endpoint (production-shape — email links etc.
// go over HTTPS). Tests override this to the http endpoint just below, because they
// run over HTTP only.
auth.WithEnvironment("PublicUrlSettings__BaseUrl", auth.GetEndpoint("https"));

if (integrationTestMode)
{
    // Skip HTTPS redirection in test mode — Linux CI runners struggle with dev certs,
    // and integration tests just need to reach /livez / controllers, not exercise TLS.
    auth.WithEnvironment("HostingSettings__HttpsRedirectionEnabled", "false");

    // Same reasoning for the OAuth token endpoint — it's hard-gated on HTTPS by
    // default in production but tests run over the http transport, so flip it off
    // alongside the redirection toggle.
    auth.WithEnvironment("ClientCredentialsSettings__RequireHttps", "false");

    // Override the BaseUrl to the http endpoint so email links emitted by the
    // controllers (password-reset, email-confirmation, lockout) point at the http
    // transport tests are using. The second WithEnvironment for the same key wins —
    // overriding the https value set above.
    auth.WithEnvironment("PublicUrlSettings__BaseUrl", auth.GetEndpoint("http"));
}

if (rateLimitingDisabled)
{
    auth.WithEnvironment("HostingSettings__RateLimitingEnabled", "false");
}

// ─── Backstage developer portal (opt-in) ─────────────────────────────────────────
// Adds a Backstage container that renders catalog-info.yaml + docs/ TechDocs.
// The image is built locally by scripts/setup-local-backstage.ps1 (or .sh) which
// scaffolds Backstage via @backstage/create-app, applies our overlay config
// (AuthenticationService.AppHost/backstage/app-config.local.yaml), and tags the
// resulting image as `authentication-service-backstage:local`.
//
// Bound to port 7007 (Backstage's convention) so docs/operations/local-backstage.md
// can hard-code the URL the user opens.
//
// If the image doesn't exist yet, the container resource fails to start with a
// clear "image not found" error — that's the signal to run the setup script. See
// docs/operations/local-backstage.md for the one-time setup walk-through.
if (withBackstage)
{
    // Repo root resolved from the AppHost's output directory. Walks up out of
    // AuthenticationService.AppHost/bin/Debug/<tfm>/ to the solution root where
    // catalog-info.yaml + docs/ live.
    var repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));

    builder.AddContainer("backstage", "authentication-service-backstage", "local")
        .WithEndpoint(name: "backstage-ui", targetPort: 7007, port: 7007, scheme: "http")
        // Catalog + docs source. Read-only mount of the repo root so Backstage
        // resolves /repo/catalog-info.yaml and `mkdocs build` runs against /repo/docs/
        // on each TechDocs request. Mounting a folder (not a single file) sidesteps
        // Docker Desktop on Windows's "mount path must be absolute" rejection of
        // single-file bind mounts.
        //
        // The overlay app-config is NOT mounted at runtime — it's baked into the
        // image by the setup script (Backstage auto-merges app-config.local.yaml
        // alongside its app-config.yaml), so the image is self-contained.
        .WithBindMount(repoRoot, "/repo", isReadOnly: true);
}

builder.Build().Run();
