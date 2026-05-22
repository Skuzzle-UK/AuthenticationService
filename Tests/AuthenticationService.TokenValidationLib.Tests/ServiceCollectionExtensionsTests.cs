using AuthenticationService.Shared.Constants;
using AwesomeAssertions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthenticationService.TokenValidationLib.Tests;

/// <summary>
/// Covers the public DI entry-point for JwtBearer wiring. Mistakes here ripple to every
/// microservice that adopts the package — options binding, scheme defaulting, ES256-only
/// algorithm restriction, MapInboundClaims=false (else 'sub' is silently rewritten to a
/// URI claim type), and role-claim-type alignment with the auth service.
/// </summary>
public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAuthenticationServiceJwt_BindsOptionsFromConfiguration()
    {
        // arrange
        var services = new ServiceCollection();
        var config = BuildConfig(authority: "https://auth.example.com", audience: "platform-api", issuer: "https://auth.example.com", requireHttps: "true");

        // act
        services.AddAuthenticationServiceJwt(config);
        using var sp = services.BuildServiceProvider();

        // assert
        var options = sp.GetRequiredService<IOptions<AuthenticationServiceOptions>>().Value;
        options.Authority.Should().Be("https://auth.example.com");
        options.Audience.Should().Be("platform-api");
        options.Issuer.Should().Be("https://auth.example.com");
        options.RequireHttpsMetadata.Should().BeTrue();
    }

    [Fact]
    public void AddAuthenticationServiceJwt_RegistersJwtBearerAsDefaultScheme()
    {
        // arrange
        var services = new ServiceCollection();
        services.AddAuthenticationServiceJwt(BuildConfig());

        // act
        using var sp = services.BuildServiceProvider();
        var authOptions = sp.GetRequiredService<IOptions<Microsoft.AspNetCore.Authentication.AuthenticationOptions>>().Value;

        // assert — both authenticate + challenge default to JwtBearer; otherwise a 401 could
        // fall through to a scheme the consumer never registered.
        authOptions.DefaultAuthenticateScheme.Should().Be(JwtBearerDefaults.AuthenticationScheme);
        authOptions.DefaultChallengeScheme.Should().Be(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void AddAuthenticationServiceJwt_ConfiguresJwtBearerWithExpectedTokenValidation()
    {
        // arrange
        var services = new ServiceCollection();
        services.AddAuthenticationServiceJwt(BuildConfig(
            authority: "https://auth.example.com",
            audience: "platform-api",
            issuer: "https://auth.example.com",
            requireHttps: "true"));
        using var sp = services.BuildServiceProvider();

        // act
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        // assert
        jwtOptions.Authority.Should().Be("https://auth.example.com");
        jwtOptions.Audience.Should().Be("platform-api");
        jwtOptions.RequireHttpsMetadata.Should().BeTrue();
        jwtOptions.MapInboundClaims.Should().BeFalse(
            because: "MapInboundClaims=true would rewrite 'sub' → a long URI claim type, breaking ClaimConstants.Sub lookups in consumers.");

        var tvp = jwtOptions.TokenValidationParameters;
        tvp.ValidateIssuer.Should().BeTrue();
        tvp.ValidateAudience.Should().BeTrue();
        tvp.ValidateLifetime.Should().BeTrue();
        tvp.ValidateIssuerSigningKey.Should().BeTrue();
        tvp.ValidIssuer.Should().Be("https://auth.example.com");
        tvp.ValidAudience.Should().Be("platform-api");
        tvp.ValidAlgorithms.Should().BeEquivalentTo([SecurityAlgorithms.EcdsaSha256],
            because: "restricting to ES256 prevents algorithm-confusion attacks (e.g. forged HS256 tokens signed with the public key).");
        tvp.NameClaimType.Should().Be(JwtRegisteredClaimNames.Name);
        tvp.RoleClaimType.Should().Be(ClaimConstants.Role,
            because: "auth service issues role claims under this exact key; mismatched key breaks [Authorize(Roles=...)].");
    }

    [Fact]
    public void AddAuthenticationServiceJwt_RequireHttpsMetadataFalse_PropagatesToJwtBearer()
    {
        // arrange — development sometimes runs auth on plain HTTP; the override must survive binding.
        var services = new ServiceCollection();
        services.AddAuthenticationServiceJwt(BuildConfig(requireHttps: "false"));
        using var sp = services.BuildServiceProvider();

        // act
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        // assert
        jwtOptions.RequireHttpsMetadata.Should().BeFalse();
    }

    [Fact]
    public void AddAuthenticationServiceJwt_ReturnsServiceCollectionForChaining()
    {
        // arrange
        var services = new ServiceCollection();

        // act
        var returned = services.AddAuthenticationServiceJwt(BuildConfig());

        // assert
        returned.Should().BeSameAs(services);
    }

    private static IConfiguration BuildConfig(
        string authority = "https://auth.example.com",
        string audience = "platform-api",
        string issuer = "https://auth.example.com",
        string requireHttps = "true")
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authority"] = authority,
                ["Audience"] = audience,
                ["Issuer"] = issuer,
                ["RequireHttpsMetadata"] = requireHttps,
            })
            .Build();
    }
}
