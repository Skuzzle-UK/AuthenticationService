﻿using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Services.Hosted;
using AuthenticationService.Settings;
using AuthenticationService.Storage;
using AuthenticationService.Validators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;

namespace AuthenticationService.Extensions;

public static class HostExtensions
{
    public static IHostBuilder ConfigureHost(this IHostBuilder host, IConfiguration config) =>
        host.ConfigureServices((context, services) =>
        {
            services.AddValidatedSettings(context);
            services.AddAutoMapper(typeof(Program));
            services.AddDatabase(context);
            services.AddSecurity(context);
            services.AddServices();
            services.AddHostedServices();
            services.AddRazorPages();
            services.AddApiControllers();
            services.AddSwagger();
            services.AddRateLimiting();
        });

    public static IServiceCollection AddValidatedSettings(this IServiceCollection services, HostBuilderContext context)
    {
        services.AddOptions<AdminAccountSeedSettings>()
            .Bind(context.Configuration.GetSection(nameof(AdminAccountSeedSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<JWTSettings>()
            .Bind(context.Configuration.GetSection(nameof(JWTSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<RevokedTokenSettings>()
            .Bind(context.Configuration.GetSection(nameof(RevokedTokenSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<EmailServerSettings>()
            .Bind(context.Configuration.GetSection(nameof(EmailServerSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return services;
    }

    public static IServiceCollection AddServices(this IServiceCollection services) =>
        services
            .AddScoped<ITokenService, JWTService>()
            .AddScoped<IUserService, UserService>()
            .AddSingleton<IEmailService, EmailService>();

    public static IServiceCollection AddHostedServices(this IServiceCollection services) =>
        services
            .AddHostedService<RevokedTokenCleanupService>();

    public static IServiceCollection AddDatabase(this IServiceCollection services, HostBuilderContext context) =>
        services
            .AddDbContext<DatabaseContext>(opt =>
            {
                opt.UseMySQL(context.Configuration.GetConnectionString("MySQL")!);
            });

    public static IServiceCollection AddSecurity(this IServiceCollection services, HostBuilderContext context)
    {
        services.AddIdentity<User, Role>(opt =>
        {
            opt.Password.RequiredLength = 8;
            opt.User.RequireUniqueEmail = true;
            opt.Lockout.AllowedForNewUsers = true;
            opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(2);
            opt.Lockout.MaxFailedAccessAttempts = 3;
        })
           .AddEntityFrameworkStores<DatabaseContext>()
           .AddPasswordValidator<CustomPasswordValidator<User>>()
           .AddDefaultTokenProviders();

        var jwtSettings = context.Configuration.GetSection("JWTSettings");

        services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(opt =>
        {
            opt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings["ValidIssuer"],
                ValidAudience = jwtSettings["ValidAudience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.GetSection("SecurityKey").Value!))
            };
        });

        services.AddAuthorizationBuilder()
            .AddPolicy("OnlyAdminUsers", policy => policy.RequireRole("Admin"));

        return services;
    }

    public static IServiceCollection AddApiControllers(this IServiceCollection services)
    {
        services
            .AddControllers()
            .AddJsonOptions(opt =>
            {
                opt.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
                opt.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
            });

        return services;
    }

    public static IServiceCollection AddSwagger(this IServiceCollection services) =>
        services
            .AddEndpointsApiExplorer()
            .AddSwaggerGen(opt =>
            {
                opt.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                opt.IncludeXmlComments(xmlPath);
            });

    public static IServiceCollection AddRateLimiting(this IServiceCollection services) =>
            services.AddRateLimiter(opt =>
            {
                opt.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                {
                    // Will check token for name first and then IP address, finally fallback to "anonymous" to decide if same user.
                    var userId = context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                    return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: userId,
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        Window = TimeSpan.FromSeconds(10),
                        PermitLimit = 4,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 2
                    });
                });
            });
}
