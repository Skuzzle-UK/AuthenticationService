using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthenticationService.TokenValidationLib;

/// <summary>
/// Registration entry point for incoming JWT validation against the central
/// AuthenticationService. Pair with <c>AddScopePolicy</c> for scope-gated endpoints.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers JwtBearer authentication validating tokens from the central auth
    /// service. Binds <see cref="AuthenticationServiceOptions"/> from
    /// <paramref name="configurationSection"/> (conventionally <c>"AuthenticationService"</c>).
    /// </summary>
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
