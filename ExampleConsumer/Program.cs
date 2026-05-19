using AuthenticationService.Client;
using AuthenticationService.Shared.Constants;
using Microsoft.OpenApi;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthenticationServiceJwt(
    builder.Configuration.GetSection("AuthenticationService"));

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(PolicyConstants.AdminOnly, p => p.RequireRole(RolesConstants.Admin))
    // Scope-based policies for service-to-service callers. Each call to AddScopePolicy
    // registers a policy of the same name that requires the JWT's `scope` claim to
    // contain that scope. Service tokens (OAuth client-credentials grant) carry the
    // claim; user tokens don't, so these policies effectively gate "machine callers only".
    .AddScopePolicy("example.read")
    .AddScopePolicy("example.write");

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(opt =>
{
    opt.SwaggerDoc("v1", new OpenApiInfo { Title = "Example Consumer API", Version = "v1" });

    opt.AddSecurityDefinition(AuthSchemeConstants.Bearer, new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Paste an access token issued by AuthenticationService (no 'Bearer ' prefix)."
    });

    opt.AddSecurityRequirement(doc => new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecuritySchemeReference(AuthSchemeConstants.Bearer, doc),
            new List<string>()
        }
    });
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello from ExampleConsumer. This endpoint is anonymous — no token required.")
    .WithName("Root");

app.MapGet("/me", (ClaimsPrincipal user) => Results.Ok(new
{
    name = user.Identity?.Name,
    isAuthenticated = user.Identity?.IsAuthenticated ?? false,
    roles = user.FindAll(ClaimConstants.Role).Select(c => c.Value),
    jti = user.FindFirstValue(ClaimConstants.Jti),
    sub = user.FindFirstValue(ClaimConstants.Sub),
}))
    .RequireAuthorization()
    .WithName("Me");

app.MapGet("/admin", () => "Welcome, admin. You see this only because the token has the Admin role.")
    .RequireAuthorization(PolicyConstants.AdminOnly)
    .WithName("AdminOnly");

// ─── Service-to-service scope-gated endpoints ────────────────────────────────────
// These endpoints demonstrate scope-based authorization for callers using the OAuth
// client-credentials grant. See README for the curl walkthrough.

app.MapGet("/example-read", (ClaimsPrincipal caller) => Results.Ok(new
{
    message = "You have example.read scope.",
    clientId = caller.FindFirstValue(ClaimConstants.ClientId),
    scopes = caller.FindFirstValue(ClaimConstants.Scope),
}))
    .RequireAuthorization("example.read")
    .WithName("ExampleRead");

app.MapPost("/example-write", (ClaimsPrincipal caller) => Results.Ok(new
{
    message = "You have example.write scope. Imagine this just mutated something.",
    clientId = caller.FindFirstValue(ClaimConstants.ClientId),
}))
    .RequireAuthorization("example.write")
    .WithName("ExampleWrite");

app.Run();
