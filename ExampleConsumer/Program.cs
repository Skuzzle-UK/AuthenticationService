using AuthenticationService.Client;
using AuthenticationService.Client.Constants;
using Microsoft.OpenApi;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthenticationServiceJwt(
    builder.Configuration.GetSection("AuthenticationService"));

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(PolicyConstants.AdminOnly, p => p.RequireRole(RolesConstants.Admin));

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
    roles = user.FindAll("role").Select(c => c.Value),
    jti = user.FindFirstValue("jti"),
    sub = user.FindFirstValue("sub"),
}))
    .RequireAuthorization()
    .WithName("Me");

app.MapGet("/admin", () => "Welcome, admin. You see this only because the token has the Admin role.")
    .RequireAuthorization(PolicyConstants.AdminOnly)
    .WithName("AdminOnly");

app.Run();
