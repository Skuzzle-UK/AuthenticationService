using AuthenticationService.Constants;
using AuthenticationService.Entities;
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
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using IPNetwork = System.Net.IPNetwork;

namespace AuthenticationService.Extensions;

public static class HostExtensions
{
    public static IHostBuilder ConfigureHost(this IHostBuilder host) =>
        host.ConfigureServices((context, services) =>
        {
            services.AddValidatedSettings(context);
            services.AddValidators();
            services.AddAutoMapper(cfg => { }, typeof(Program));
            services.AddDatabase(context);
            services.AddSecurity();
            services.AddDataProtectionConfiguration(context);
            services.AddForwardedHeadersConfiguration(context);
            services.AddCorsConfiguration(context);
            services.AddHealthChecksConfiguration();
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

        return services;
    }

    /// <summary>
    /// Registers freestanding <c>IValidateOptions&lt;T&gt;</c> implementations that go
    /// beyond the data-annotations validation wired up in <see cref="AddValidatedSettings"/>.
    /// These run at startup via the <c>ValidateOnStart()</c> chain on each settings
    /// registration, so any failure here surfaces as a startup exception with a clear
    /// message rather than a runtime surprise.
    ///
    /// <para>Identity-pipeline validators (<c>IUserValidator&lt;User&gt;</c>,
    /// <c>IPasswordValidator&lt;User&gt;</c>) are not registered here — they live in
    /// <see cref="AddSecurity"/> because they hang off the <c>AddIdentity</c> builder.</para>
    /// </summary>
    public static IServiceCollection AddValidators(this IServiceCollection services)
    {
        services.AddSingleton<IValidateOptions<AdminAccountSeedSettings>, AdminAccountSeedSettingsValidator>();

        return services;
    }

    public static IServiceCollection AddServices(this IServiceCollection services) =>
        services
            .AddSingleton<IEcdsaKeyProvider, EcdsaKeyProvider>()
            .AddScoped<ITokenService, JWTService>()
            .AddScoped<IUserService, UserService>()
            .AddSingleton<IEmailService, EmailService>();

    public static IServiceCollection AddHostedServices(this IServiceCollection services) =>
        services
            .AddHostedService<DataRetentionService>();

    public static IServiceCollection AddDatabase(this IServiceCollection services, HostBuilderContext context) =>
        services
            .AddDbContext<DatabaseContext>(opt =>
            {
                opt.UseMySQL(context.Configuration.GetConnectionString("MySQL")!);
            });

    public static IServiceCollection AddSecurity(this IServiceCollection services)
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
    /// Wires up ASP.NET Core's data-protection key ring. Keys are persisted to Redis
    /// so the ring is shared across replicas and survives restarts;
    /// otherwise outstanding password-reset / email-confirmation / MFA / lockout
    /// tokens would be invalidated whenever a replica restarts. If a protection certificate
    /// is configured, keys are encrypted at rest with it; without the cert, keys sit in
    /// Redis as readable XML — acceptable for a transitional rollout behind a controlled
    /// network, but `Certificate` should be populated before the service is exposed to
    /// anything sensitive.
    /// </summary>
    public static IServiceCollection AddDataProtectionConfiguration(
        this IServiceCollection services,
        HostBuilderContext context)
    {
        var settings = context.Configuration
            .GetSection(nameof(DataProtectionSettings))
            .Get<DataProtectionSettings>() ?? new DataProtectionSettings();

        var redisConnectionString = context.Configuration.GetConnectionString("Redis");

        if (string.IsNullOrWhiteSpace(redisConnectionString))
        {
            throw new InvalidOperationException(
                "ConnectionStrings:Redis must be configured. The data-protection key ring " +
                "is persisted to Redis so it survives restarts and is shared across replicas; " +
                "without it, every outstanding email-link token (password reset, email " +
                "confirmation, MFA, lockout) would be invalidated on each restart. " +
                "For local development, run a Redis container (e.g. " +
                "`docker run -d -p 6379:6379 redis:alpine`) or install Redis locally.");
        }

        var redis = StackExchange.Redis.ConnectionMultiplexer.Connect(redisConnectionString);

        // Register the multiplexer so other components (e.g. the Redis health check) can
        // share the same connection rather than opening a second one.
        services.AddSingleton<StackExchange.Redis.IConnectionMultiplexer>(redis);

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
    /// Configures the <see cref="ForwardedHeadersOptions"/> from
    /// <see cref="ForwardedHeadersSettings"/>. The actual middleware (<c>UseForwardedHeaders</c>)
    /// is hooked into the pipeline by <c>WebApplicationExtensions.ConfigureApplication</c>.
    ///
    /// Honours <c>X-Forwarded-For</c> and <c>X-Forwarded-Proto</c> from trusted upstreams only.
    /// <c>X-Forwarded-Host</c> is intentionally not honoured — host-header attacks (cache
    /// poisoning, password-reset link manipulation) become possible if a malicious upstream
    /// can override Host. Most LB deploys preserve the original Host header without needing
    /// the override.
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

            // The framework defaults to trusting localhost-loopback proxies. Clear that —
            // we want explicit trust, no implicit defaults.
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
            .AddDbContextCheck<DatabaseContext>("database", tags: ["ready"])
            .AddCheck<RedisHealthCheck>("redis", tags: ["ready"]);

        return services;
    }

    /// <summary>
    /// Configures the default CORS policy from <see cref="CorsSettings"/>. Origins must be
    /// explicitly allow-listed; an empty <c>AllowedOrigins</c> list yields a default policy
    /// that blocks all cross-origin traffic. Methods and headers are pinned to what the API
    /// actually uses; <c>AllowCredentials</c> is intentionally off because JWT bearer tokens
    /// travel in the Authorization header, not in cookies.
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
                    // No origins configured — leave the policy empty, which blocks all
                    // cross-origin traffic. Fail-closed, not fail-open.
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

    public static IServiceCollection AddRateLimiting(this IServiceCollection services) =>
            services.AddRateLimiter(opt =>
            {
                // Global limiter applies to every request and acts as the catch-all default.
                // Endpoints with a stricter named policy attached are subject to BOTH limiters
                // (most-restrictive wins).
                opt.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                {
                    // Health-check endpoints get a permissive bucket — orchestrator + monitoring
                    // probes fire frequently (especially during startup) and shouldn't be throttled
                    // alongside regular API traffic. Still rate-limited to cap DDoS abuse on the
                    // anonymous health endpoints.
                    if (context.Request.Path.StartsWithSegments("/healthz")
                        || context.Request.Path.StartsWithSegments("/readyz"))
                    {
                        var probeIp = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                        return RateLimitPartition.GetFixedWindowLimiter(
                            partitionKey: $"health:{probeIp}",
                            factory: _ => new FixedWindowRateLimiterOptions
                            {
                                Window = TimeSpan.FromSeconds(10),
                                PermitLimit = 30,
                                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                                QueueLimit = 0
                            });
                    }

                    // Default partition: per-user once authenticated, per-IP otherwise.
                    var userId = context.User?.FindFirst(ClaimConstants.Sub)?.Value
                                 ?? context.Connection.RemoteIpAddress?.ToString()
                                 ?? "anonymous";

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

                // Strict per-IP cap for unauthenticated credential/link endpoints.
                // 10/minute leaves headroom for shared NAT (corporate / family) but pins
                // automated credential stuffing well below useful throughput.
                opt.AddPolicy(RateLimitPolicies.AuthStrict, context =>
                {
                    var ip = context.Connection.RemoteIpAddress?.ToString() ?? "anonymous";
                    return RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: $"auth-strict:{ip}",
                        factory: _ => new FixedWindowRateLimiterOptions
                        {
                            Window = TimeSpan.FromMinutes(1),
                            PermitLimit = 10,
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 0
                        });
                });

                // Per-user cap for authenticated state-changing endpoints.
                opt.AddPolicy(RateLimitPolicies.AuthSensitive, context =>
                {
                    var key = context.User?.FindFirst(ClaimConstants.Sub)?.Value
                              ?? context.Connection.RemoteIpAddress?.ToString()
                              ?? "anonymous";
                    return RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: $"auth-sensitive:{key}",
                        factory: _ => new FixedWindowRateLimiterOptions
                        {
                            Window = TimeSpan.FromMinutes(1),
                            PermitLimit = 10,
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 0
                        });
                });

                // Reject with 429 and a hint, rather than letting requests pile up silently.
                opt.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            });
}
