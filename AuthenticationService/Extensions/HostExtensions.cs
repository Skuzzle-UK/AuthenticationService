using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Storage;
using AuthenticationService.Validators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

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
            services.AddControllers()
                .AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
                    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                });
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

        services.AddOptions<EmailServerSettings>()
            .Bind(context.Configuration.GetSection(nameof(EmailServerSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return services;
    }

    public static IServiceCollection AddServices(this IServiceCollection services) =>
        services
            .AddSingleton<ITokenService, JWTService>()
            .AddSingleton<IEmailService, EmailService>();

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
}
