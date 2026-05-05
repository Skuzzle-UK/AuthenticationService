using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthenticationService.Client;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers JwtBearer authentication that validates tokens issued by the central
    /// authentication service. Reads <see cref="AuthenticationServiceOptions"/> from the
    /// supplied configuration section and discovers signing keys via the issuer's JWKS endpoint.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configurationSection">
    /// Configuration section containing <c>Authority</c>, <c>Audience</c>, and optionally
    /// <c>RequireHttpsMetadata</c>. Conventionally bound from
    /// <c>"AuthenticationService"</c> in appsettings.
    /// </param>
    public static IServiceCollection AddAuthenticationServiceJwt(
        this IServiceCollection services,
        IConfiguration configurationSection)
    {
        services.AddOptions<AuthenticationServiceOptions>()
            .Bind(configurationSection)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<AuthenticationServiceOptions>>((opt, authOptions) =>
            {
                var settings = authOptions.Value;
                opt.Authority = settings.Authority;
                opt.Audience = settings.Audience;
                opt.RequireHttpsMetadata = settings.RequireHttpsMetadata;
                opt.MapInboundClaims = false;
                opt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = settings.Issuer,
                    ValidAudience = settings.Audience,
                    ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
                    NameClaimType = JwtRegisteredClaimNames.Name,
                    RoleClaimType = ClaimConstants.Role
                };
            });

        return services;
    }
}
