using AuthenticationService.Shared.Constants;
using AwesomeAssertions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AuthenticationService.Client.Tests;

/// <summary>
/// <para>This extension is the public entry-point consumers call to wire up JwtBearer against
/// the central auth service. Mistakes here ripple to every microservice that adopts the package.
/// We verify:</para>
/// <list type="bullet">
///   <item><description>Options are bound from the supplied configuration section — operators set values in JSON / env vars and expect them to land on <see cref="AuthenticationServiceOptions"/>.</description></item>
///   <item><description><see cref="JwtBearerDefaults.AuthenticationScheme"/> is registered as both default-authenticate and default-challenge — a regression here would change which scheme protects endpoints.</description></item>
///   <item><description>The configured <see cref="JwtBearerOptions"/> propagate Authority / Audience / Issuer / RequireHttpsMetadata correctly, restrict signing algorithms to ES256 (no algorithm-confusion risk), use the standard <c>name</c> claim, and use the auth service's <c>role</c> claim type for <c>[Authorize(Roles=...)]</c> to work.</description></item>
///   <item><description><c>MapInboundClaims = false</c> — without this, .NET silently rewrites <c>sub</c> to a long URI claim type, breaking any code that reads <see cref="ClaimConstants.Sub"/>.</description></item>
/// </list>
/// </summary>
public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAuthenticationServiceJwt_BindsOptionsFromConfiguration()
    {
        // arrange — config section a real consumer would supply.
        var services = new ServiceCollection();
        var config = BuildConfig(authority: "https://auth.example.com", audience: "platform-api", issuer: "https://auth.example.com", requireHttps: "true");

        // act
        services.AddAuthenticationServiceJwt(config);
        using var sp = services.BuildServiceProvider();

        // assert — the bound IOptions reflect the supplied values, proving the binding pipeline is wired.
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

        // assert — both authenticate and challenge default to JwtBearer; otherwise a 401 might
        // unexpectedly fall through to a different scheme that the consumer never registered.
        authOptions.DefaultAuthenticateScheme.Should().Be(JwtBearerDefaults.AuthenticationScheme);
        authOptions.DefaultChallengeScheme.Should().Be(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void AddAuthenticationServiceJwt_ConfiguresJwtBearerWithExpectedTokenValidation()
    {
        // arrange — a typical production config.
        var services = new ServiceCollection();
        services.AddAuthenticationServiceJwt(BuildConfig(
            authority: "https://auth.example.com",
            audience: "platform-api",
            issuer: "https://auth.example.com",
            requireHttps: "true"));
        using var sp = services.BuildServiceProvider();

        // act — resolve the JwtBearer options that ASP.NET Core would actually use at runtime.
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        // assert — every value the consumer needs to be tamper-proof.
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
        // arrange — Development sometimes runs auth on plain HTTP. Verify the override survives.
        var services = new ServiceCollection();
        services.AddAuthenticationServiceJwt(BuildConfig(requireHttps: "false"));
        using var sp = services.BuildServiceProvider();

        // act
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        // assert — operator opt-in honoured.
        jwtOptions.RequireHttpsMetadata.Should().BeFalse();
    }

    [Fact]
    public void AddAuthenticationServiceJwt_ReturnsServiceCollectionForChaining()
    {
        // arrange — builder-pattern contract: the returned IServiceCollection lets callers chain.
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
