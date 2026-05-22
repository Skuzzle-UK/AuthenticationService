using AwesomeAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// Covers the public DI entry point for outgoing-token plumbing. The cache +
/// per-key-semaphore design only works if the provider is a singleton — anything else
/// gives every caller a fresh empty cache.
/// </summary>
public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAuthenticationServiceTokenClient_RegistersProviderAsSingleton()
    {
        // arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // act
        services.AddAuthenticationServiceTokenClient(BuildConfig());

        // assert
        var descriptor = services.Single(d => d.ServiceType == typeof(IServiceTokenProvider));
        descriptor.Lifetime.Should().Be(ServiceLifetime.Singleton,
            because: "the cache + per-key semaphores need to be shared across every caller in the process. " +
                     "A scoped/transient lifetime would mean a fresh cache per request, defeating the whole point.");
    }

    [Fact]
    public void AddAuthenticationServiceTokenClient_ResolvesSameProviderInstanceAcrossScopes()
    {
        // arrange
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthenticationServiceTokenClient(BuildConfig());
        using var sp = services.BuildServiceProvider();

        // act
        using var scope1 = sp.CreateScope();
        using var scope2 = sp.CreateScope();
        var p1 = scope1.ServiceProvider.GetRequiredService<IServiceTokenProvider>();
        var p2 = scope2.ServiceProvider.GetRequiredService<IServiceTokenProvider>();

        // assert
        p1.Should().BeSameAs(p2);
    }

    [Fact]
    public void AddAuthenticationServiceTokenClient_BindsOptionsFromConfiguration()
    {
        // arrange
        var services = new ServiceCollection();
        services.AddLogging();
        var config = BuildConfig(
            authority: "https://auth.example.com",
            clientId: "orders-service",
            clientSecret: "rotated-secret");

        // act
        services.AddAuthenticationServiceTokenClient(config);
        using var sp = services.BuildServiceProvider();

        // assert
        var options = sp.GetRequiredService<IOptions<ServiceTokenClientOptions>>().Value;
        options.Authority.Should().Be("https://auth.example.com");
        options.ClientId.Should().Be("orders-service");
        options.ClientSecret.Should().Be("rotated-secret");
    }

    [Fact]
    public void AddAuthenticationServiceTokenClient_RegistersNamedHttpClient()
    {
        // arrange
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthenticationServiceTokenClient(BuildConfig());
        using var sp = services.BuildServiceProvider();

        // act
        var factory = sp.GetRequiredService<IHttpClientFactory>();
        using var http = factory.CreateClient(ServiceTokenProvider.HttpClientName);

        // assert — 30s timeout distinguishes our configured registration from the framework default (~100s).
        http.Timeout.Should().Be(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void AddAuthenticationServiceTokenClient_ReturnsServiceCollectionForChaining()
    {
        // arrange
        var services = new ServiceCollection();
        services.AddLogging();

        // act
        var returned = services.AddAuthenticationServiceTokenClient(BuildConfig());

        // assert
        returned.Should().BeSameAs(services);
    }

    private static IConfiguration BuildConfig(
        string authority = "https://auth.example.com",
        string clientId = "orders-service",
        string clientSecret = "super-secret")
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authority"] = authority,
                ["ClientId"] = clientId,
                ["ClientSecret"] = clientSecret,
            })
            .Build();
    }
}
