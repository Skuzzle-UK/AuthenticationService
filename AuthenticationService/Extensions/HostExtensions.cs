using AuthenticationService.Entities;
using AuthenticationService.Logging;
using AuthenticationService.Observability;
using AuthenticationService.Services;
using AuthenticationService.Services.HealthChecks;
using AuthenticationService.Services.Hosted;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Storage;
using AuthenticationService.Validators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using Serilog.Core;
using StackExchange.Redis;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using IPNetwork = System.Net.IPNetwork;
using Role = AuthenticationService.Entities.Role;

namespace AuthenticationService.Extensions;

public static class HostExtensions
{
    public static IHostBuilder ConfigureHost(this IHostBuilder host) =>
        host.ConfigureServices((context, services) =>
        {
            services.AddValidatedSettings(context);
            services.AddValidators();
            services.AddDatabase(context);
            services.AddRedis(context);
            services.AddSecurity(context);
            services.AddDataProtectionConfiguration(context);
            services.AddForwardedHeadersConfiguration(context);
            services.AddCorsConfiguration(context);
            services.AddHealthChecksConfiguration();
            services.AddProblemDetailsConfiguration();
            services.AddServices();
            services.AddHostedServices(context);
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

        services.AddOptions<DataRetentionSettings>()
            .Bind(context.Configuration.GetSection(nameof(DataRetentionSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<DataProtectionSettings>()
            .Bind(context.Configuration.GetSection(nameof(DataProtectionSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<ForwardedHeadersSettings>()
            .Bind(context.Configuration.GetSection(nameof(ForwardedHeadersSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<CorsSettings>()
            .Bind(context.Configuration.GetSection(nameof(CorsSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<EmailServerSettings>()
            .Bind(context.Configuration.GetSection(nameof(EmailServerSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<PublicUrlSettings>()
            .Bind(context.Configuration.GetSection(nameof(PublicUrlSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<ThresholdEscalationSettings>()
            .Bind(context.Configuration.GetSection(nameof(ThresholdEscalationSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<HostingSettings>()
            .Bind(context.Configuration.GetSection(nameof(HostingSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<IdentitySettings>()
            .Bind(context.Configuration.GetSection(nameof(IdentitySettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<ClientCredentialsSettings>()
            .Bind(context.Configuration.GetSection(nameof(ClientCredentialsSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return services;
    }

    /// <summary>
    /// Freestanding <c>IValidateOptions&lt;T&gt;</c> registrations beyond the
    /// data-annotation validation in <see cref="AddValidatedSettings"/>. Identity-pipeline
    /// validators live in <see cref="AddSecurity"/> instead — they hang off AddIdentity.
    /// </summary>
    public static IServiceCollection AddValidators(this IServiceCollection services)
    {
        services.AddSingleton<IValidateOptions<AdminAccountSeedSettings>, AdminAccountSeedSettingsValidator>();

        return services;
    }

    public static IServiceCollection AddServices(this IServiceCollection services)
    {
        services
            .AddSingleton<IEcdsaKeyProvider, EcdsaKeyProvider>()
            .AddScoped<ITokenService, JWTService>()
            .AddScoped<IUserService, UserService>()
            // TODO: replace with a real provider (Twilio, SNS, etc.). Stub reports
            // IsConfigured = false so phone MFA endpoints cleanly BadRequest.
            .AddSingleton<ISmsService, SmsService>()
            .AddHttpContextAccessor()
            .AddSingleton<ILogEventEnricher, HttpContextLogEnricher>()
            .AddSingleton<QueuedEmailService>()
            .AddSingleton<IEmailService>(sp => sp.GetRequiredService<QueuedEmailService>())
            .AddSingleton<AuthMetrics>()
            .AddScoped<IAdminService, AdminService>()
            // IPasswordHasher<Client> reuses Identity's standard hasher so s2s secrets land
            // in the DB with the same algorithm + iteration count as user passwords.
            .AddScoped<IClientService, ClientService>()
            .AddScoped<IPasswordHasher<Client>, PasswordHasher<Client>>();

        return services;
    }

    public static IServiceCollection AddHostedServices(this IServiceCollection services, HostBuilderContext context)
    {
        // Runs on every replica.
        services
            .AddHostedService(sp => sp.GetRequiredService<QueuedEmailService>());

        // Gated so a multi-replica deployment can split into API pods (workers off) and
        // a single worker pod (workers on).
        var hostingSettings = context.Configuration
            .GetSection(nameof(HostingSettings))
            .Get<HostingSettings>() ?? new HostingSettings();

        if (!hostingSettings.BackgroundWorkersEnabled)
        {
            return services;
        }

        return services
            .AddHostedService<DataRetentionCleanupService>()
            .AddHostedService<RevokedTokenReplayEscalationService>()
            .AddHostedService<UserGaugeRefreshService>();
    }

    public static IServiceCollection AddDatabase(this IServiceCollection services, HostBuilderContext context) =>
        services
            .AddDbContext<DatabaseContext>(opt =>
            {
                opt.UseMySQL(
                    context.Configuration.GetConnectionString("MySQL")!,
                    mysql =>
                    {
                        // See Storage/MySqlRetryingExecutionStrategy.cs for rationale.
                        mysql.ExecutionStrategy(deps => new MySqlRetryingExecutionStrategy(deps));
                    });
            });

    public static IServiceCollection AddRedis(this IServiceCollection services, HostBuilderContext context)
    {
        var redisConnectionString = context.Configuration.GetConnectionString("Redis");

        if (string.IsNullOrWhiteSpace(redisConnectionString))
        {
            throw new InvalidOperationException(
                "ConnectionStrings:Redis must be configured. The data-protection key ring " +
                "is persisted to Redis so it survives restarts and is shared across replicas; " +
                "the rate limiter writes its state there too. " +
                "For local development, run a Redis container (e.g. " +
                "`docker run -d -p 6379:6379 redis:alpine`) or install Redis locally.");
        }

        var configOptions = ConfigurationOptions.Parse(redisConnectionString);
        configOptions.AbortOnConnectFail = false;
        var redis = ConnectionMultiplexer.Connect(configOptions);

        services.AddSingleton<IConnectionMultiplexer>(redis);

        return services;
    }

    public static IServiceCollection AddSecurity(this IServiceCollection services, HostBuilderContext context)
    {
        // Read eagerly — AddIdentity needs the values up front. Validation runs via
        // ValidateOnStart() in AddValidatedSettings, not here.
        var identitySettings = context.Configuration
            .GetSection(nameof(IdentitySettings))
            .Get<IdentitySettings>() ?? new IdentitySettings();

        services.AddIdentity<User, Role>(opt =>
        {
            opt.Password.RequiredLength = identitySettings.Password.RequiredLength;
            opt.Password.RequireDigit = identitySettings.Password.RequireDigit;
            opt.Password.RequireLowercase = identitySettings.Password.RequireLowercase;
            opt.Password.RequireUppercase = identitySettings.Password.RequireUppercase;
            opt.Password.RequireNonAlphanumeric = identitySettings.Password.RequireNonAlphanumeric;
            opt.Password.RequiredUniqueChars = identitySettings.Password.RequiredUniqueChars;

            opt.User.RequireUniqueEmail = identitySettings.User.RequireUniqueEmail;
            opt.User.AllowedUserNameCharacters = identitySettings.User.AllowedUserNameCharacters;

            opt.Lockout.AllowedForNewUsers = identitySettings.Lockout.AllowedForNewUsers;
            opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(identitySettings.Lockout.DefaultLockoutDurationInMinutes);
            opt.Lockout.MaxFailedAccessAttempts = identitySettings.Lockout.MaxFailedAccessAttempts;
        })
           .AddEntityFrameworkStores<DatabaseContext>()
           .AddPasswordValidator<CustomPasswordValidator<User>>()
           .AddUserValidator<ReservedUserNameValidator>()
           .AddDefaultTokenProviders();

        services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IEcdsaKeyProvider, IOptions<JWTSettings>>((opt, keyProvider, jwtOptions) =>
            {
                var jwt = jwtOptions.Value;
                opt.MapInboundClaims = false;
                opt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwt.ValidIssuer,
                    ValidAudience = jwt.ValidAudience,
                    IssuerSigningKeys = keyProvider.PublicSecurityKeys,
                    ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
                    NameClaimType = ClaimConstants.Name,
                    RoleClaimType = ClaimConstants.Role
                };
            });

        services.AddAuthorizationBuilder()
            .AddPolicy(PolicyConstants.AdminOnly, policy => policy.RequireRole(RolesConstants.Admin));

        return services;
    }

    /// <summary>
    /// Wires up the data-protection key ring. Keys are persisted to Redis so they survive
    /// restarts and are shared across replicas (otherwise outstanding reset / MFA /
    /// confirmation tokens would be invalidated on every restart). Without a configured
    /// <see cref="DataProtectionSettings.Certificate"/> the keys sit in Redis as readable
    /// XML — populate before exposing the service to anything sensitive.
    /// </summary>
    public static IServiceCollection AddDataProtectionConfiguration(
        this IServiceCollection services,
        HostBuilderContext context)
    {
        var settings = context.Configuration
        .GetSection(nameof(DataProtectionSettings))
        .Get<DataProtectionSettings>() ?? new DataProtectionSettings();

        // Temp provider is deliberate — the lazy Func<IDatabase> overload would build a
        // fresh provider on every key-ring read.
        using var tempProvider = services.BuildServiceProvider();
        var redis = tempProvider.GetRequiredService<IConnectionMultiplexer>();

        var builder = services.AddDataProtection()
            .SetApplicationName(settings.ApplicationName)
            .PersistKeysToStackExchangeRedis(redis, settings.RedisKey);

        if (!string.IsNullOrWhiteSpace(settings.Certificate?.PfxPath))
        {
            var cert = X509CertificateLoader.LoadPkcs12FromFile(
                settings.Certificate.PfxPath,
                settings.Certificate.PfxPassword);

            builder.ProtectKeysWithCertificate(cert);
        }

        return services;
    }

    /// <summary>
    /// Configures <see cref="ForwardedHeadersOptions"/> from <see cref="ForwardedHeadersSettings"/>.
    /// X-Forwarded-Host is deliberately not honoured — host-header attacks (cache poisoning,
    /// reset-link manipulation) become possible if an upstream can override Host.
    /// </summary>
    public static IServiceCollection AddForwardedHeadersConfiguration(
        this IServiceCollection services,
        HostBuilderContext context)
    {
        var settings = context.Configuration
            .GetSection(nameof(ForwardedHeadersSettings))
            .Get<ForwardedHeadersSettings>() ?? new ForwardedHeadersSettings();

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

            // Clear the framework's implicit loopback trust — explicit only.
            options.KnownIPNetworks.Clear();
            options.KnownProxies.Clear();

            foreach (var network in settings.KnownNetworks)
            {
                options.KnownIPNetworks.Add(IPNetwork.Parse(network));
            }

            foreach (var proxy in settings.KnownProxies)
            {
                options.KnownProxies.Add(IPAddress.Parse(proxy));
            }
        });

        return services;
    }

    public static IServiceCollection AddHealthChecksConfiguration(this IServiceCollection services)
    {
        services.AddHealthChecks()
            .AddCheck("self", () => HealthCheckResult.Healthy(), tags: ["live"])
            .AddCheck<MySqlHealthCheck>("database", tags: ["ready"])
            .AddCheck<RedisHealthCheck>("redis", tags: ["ready"]);

        return services;
    }

    /// <summary>
    /// RFC 7807 Problem Details for unhandled exceptions and unhandled status codes.
    /// Paired with <c>UseExceptionHandler()</c> + <c>UseStatusCodePages()</c> in the
    /// pipeline. Always stamps a <c>traceId</c> so operators can grep correlated logs.
    /// </summary>
    public static IServiceCollection AddProblemDetailsConfiguration(this IServiceCollection services)
    {
        services.AddProblemDetails(opt =>
        {
            opt.CustomizeProblemDetails = ctx =>
            {
                ctx.ProblemDetails.Extensions["traceId"] =
                    Activity.Current?.Id ?? ctx.HttpContext.TraceIdentifier;
            };
        });

        return services;
    }

    /// <summary>
    /// Default CORS policy from <see cref="CorsSettings"/>. Origins are explicit allow-list;
    /// AllowCredentials is off because JWT bearer tokens travel in Authorization, not cookies.
    /// </summary>
    public static IServiceCollection AddCorsConfiguration(
        this IServiceCollection services,
        HostBuilderContext context)
    {
        var settings = context.Configuration
            .GetSection(nameof(CorsSettings))
            .Get<CorsSettings>() ?? new CorsSettings();

        services.AddCors(options =>
        {
            options.AddDefaultPolicy(builder =>
            {
                if (settings.AllowedOrigins.Count == 0)
                {
                    // Empty policy blocks all cross-origin traffic — fail-closed.
                    return;
                }

                builder
                    .WithOrigins([.. settings.AllowedOrigins])
                    .WithMethods("GET", "POST", "OPTIONS")
                    .WithHeaders("Authorization", "Content-Type", "Accept");
            });
        });

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
                opt.SwaggerDoc("v1", new OpenApiInfo { Title = "Authentication API", Version = "v1" });
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                opt.IncludeXmlComments(xmlPath);

                opt.AddSecurityDefinition(AuthSchemeConstants.Bearer, new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "Paste the JWT access token (without the 'Bearer ' prefix)."
                });

                opt.AddSecurityRequirement(doc => new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecuritySchemeReference(AuthSchemeConstants.Bearer, doc),
                        new List<string>()
                    }
                });
            });

    /// <summary>
    /// Wires up the rate limiter. Configuration is in <see cref="RateLimiterOptionsConfigurator"/>,
    /// registered as <see cref="IConfigureOptions{TOptions}"/> so it can ctor-inject the Redis
    /// multiplexer at options-resolve time.
    /// </summary>
    public static IServiceCollection AddRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(_ => { });
        services.AddSingleton<IConfigureOptions<RateLimiterOptions>, RateLimiterOptionsConfigurator>();
        return services;
    }
}
