var builder = DistributedApplication.CreateBuilder(args);

// Two independent test-mode flags, both passed by integration-test fixtures:
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
// Real F5 passes neither, so dev / prod behaviour is identical to a plain run.
var integrationTestMode = args.Contains("--integration-test");
var rateLimitingDisabled = args.Contains("--rate-limiting-disabled");

var smtp = builder.AddContainer("smtp4dev", "rnwood/smtp4dev")
    .WithEndpoint(name: "smtp", targetPort: 25)
    .WithHttpEndpoint(name: "http", targetPort: 80);

var mysql = builder.AddMySql("mysql");
var authDb = mysql.AddDatabase("AuthenticationService");

var redis = builder.AddRedis("redis")
    .WithRedisInsight();

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

// Default: BaseUrl points at the https endpoint (production-shape — email links etc.
// go over HTTPS). Tests override this to the http endpoint just below, because they
// run over HTTP only.
auth.WithEnvironment("PublicUrlSettings__BaseUrl", auth.GetEndpoint("https"));

if (integrationTestMode)
{
    // Skip HTTPS redirection in test mode — Linux CI runners struggle with dev certs,
    // and integration tests just need to reach /livez / controllers, not exercise TLS.
    auth.WithEnvironment("HostingSettings__HttpsRedirectionEnabled", "false");

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

builder.Build().Run();
