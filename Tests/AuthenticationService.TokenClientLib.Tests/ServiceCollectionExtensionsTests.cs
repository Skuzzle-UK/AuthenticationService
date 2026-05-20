using AwesomeAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// <para>This extension is the public entry point consumers call to wire up
/// outgoing-token plumbing. The whole cache + per-key-semaphore design only works if the
/// provider is a single instance for the process — register it scoped/transient and every
/// request gets a fresh empty cache. So we pin:</para>
/// <list type="bullet">
///   <item><description><c>IServiceTokenProvider</c> is registered with <see cref="ServiceLifetime.Singleton"/> — the cache + thundering-herd protection both rely on it.</description></item>
///   <item><description>Options are bound from the supplied configuration section — operators set values in JSON / env vars and expect them to land on <see cref="ServiceTokenClientOptions"/>.</description></item>
///   <item><description>A named <c>HttpClient</c> is registered under the <see cref="ServiceTokenProvider.HttpClientName"/> constant — the provider pulls it via <c>IHttpClientFactory</c>, so a missing registration would break the very first token request with a not-very-helpful error.</description></item>
///   <item><description>The fluent return value is the same <see cref="IServiceCollection"/> for chaining.</description></item>
/// </list>
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

        // assert — the descriptor must be Singleton; anything else defeats the per-process cache.
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

        // act — pull the provider via two independent scopes. Singletons must round-trip identical.
        using var scope1 = sp.CreateScope();
        using var scope2 = sp.CreateScope();
        var p1 = scope1.ServiceProvider.GetRequiredService<IServiceTokenProvider>();
        var p2 = scope2.ServiceProvider.GetRequiredService<IServiceTokenProvider>();

        // assert — reference equality. Two distinct instances would each carry their own cache.
        p1.Should().BeSameAs(p2);
    }

    [Fact]
    public void AddAuthenticationServiceTokenClient_BindsOptionsFromConfiguration()
    {
        // arrange — config a real consumer would supply.
        var services = new ServiceCollection();
        services.AddLogging();
        var config = BuildConfig(
            authority: "https://auth.example.com",
            clientId: "orders-service",
            clientSecret: "rotated-secret");

        // act
        services.AddAuthenticationServiceTokenClient(config);
        using var sp = services.BuildServiceProvider();

        // assert — bound IOptions reflect the supplied values, proving the binding pipeline is wired.
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

        // act — pull the factory + ask for the named client the provider expects.
        var factory = sp.GetRequiredService<IHttpClientFactory>();
        using var http = factory.CreateClient(ServiceTokenProvider.HttpClientName);

        // assert — the registration applies our 30s timeout, which is how we recognise the
        // configured registration rather than the framework's default (~100s) for unknown names.
        http.Timeout.Should().Be(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void AddAuthenticationServiceTokenClient_ReturnsServiceCollectionForChaining()
    {
        // arrange — builder-pattern contract: the returned IServiceCollection lets callers chain.
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
