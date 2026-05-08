var builder = DistributedApplication.CreateBuilder(args);

// Tests pass --integration-test via DistributedApplicationTestingBuilder.CreateAsync.
// Real F5 doesn't, so production / dev keep their normal limits. The flag flows into
// the auth project as a HostingSettings override; the rate limiter checks it and
// installs a no-op limiter when set.
//
// Why this is here and not in appsettings: we want F5 to use rate limits (so dev
// behaviour matches prod) and tests to skip them (so a sequence of credential calls
// across scenarios doesn't trip the global 4/10s cap). Detecting test mode via args is
// the cleanest split — appsettings.Development.json would also disable for plain F5.
var integrationTestMode = args.Contains("--integration-test");

var smtp = builder.AddContainer("smtp4dev", "rnwood/smtp4dev")
    .WithEndpoint(name: "smtp", targetPort: 25)
    .WithHttpEndpoint(name: "http", targetPort: 80);

var mysql = builder.AddMySql("mysql");
var authDb = mysql.AddDatabase("AuthenticationService");

var redis = builder.AddRedis("redis")
    .WithRedisInsight();

var auth = builder.AddProject<Projects.AuthenticationService>("auth")
    .WithEnvironment("EmailServerSettings__SmtpServer", smtp.GetEndpoint("smtp").Property(EndpointProperty.Host))
    .WithEnvironment("EmailServerSettings__Port", smtp.GetEndpoint("smtp").Property(EndpointProperty.Port))
    .WithEnvironment("EmailServerSettings__UserName", "")
    .WithEnvironment("EmailServerSettings__Password", "")
    .WithEnvironment("ConnectionStrings__MySQL", authDb)
    .WithEnvironment("ConnectionStrings__Redis", redis)
    .WaitFor(authDb)
    .WaitFor(redis)
    .WaitFor(smtp);

auth.WithEnvironment("PublicUrlSettings__BaseUrl", auth.GetEndpoint("https"));

if (integrationTestMode)
{
    auth.WithEnvironment("HostingSettings__RateLimitingEnabled", "false");
}

builder.Build().Run();
