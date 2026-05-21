using AwesomeAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// Covers the per-typed-client AddServiceToken extension. Bad arguments fail at
/// registration time, and the handler landing in the pipeline is a real ServiceTokenHandler
/// pulled from DI.
/// </summary>
public class HttpClientBuilderExtensionsTests
{
    [Fact]
    public void AddServiceToken_EmptyAudience_Throws()
    {
        var services = new ServiceCollection();
        var builder = services.AddHttpClient("test-client");

        var act = () => builder.AddServiceToken(audience: "  ", scopes: "any.scope");

        act.Should().Throw<ArgumentException>().WithMessage("*audience*");
    }

    [Fact]
    public void AddServiceToken_NoScopes_Throws()
    {
        var services = new ServiceCollection();
        var builder = services.AddHttpClient("test-client");

        var act = () => builder.AddServiceToken(audience: "inventory-api");

        act.Should().Throw<ArgumentException>().WithMessage("*scope*");
    }

    [Fact]
    public void AddServiceToken_RegistersServiceTokenHandlerInTheTypedClientPipeline()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IServiceTokenProvider>());
        services.AddHttpClient("test-client").AddServiceToken("inventory-api", "inventory.read");

        using var sp = services.BuildServiceProvider();

        // IHttpMessageHandlerFactory builds the full chain on demand; framework wraps
        // in LifetimeTrackingHttpMessageHandler so walk InnerHandler rather than match root.
        var handlerFactory = sp.GetRequiredService<IHttpMessageHandlerFactory>();
        using var handler = handlerFactory.CreateHandler("test-client");

        var found = false;
        var current = handler;
        var depth = 0;
        while (current is DelegatingHandler dh && depth++ < 10)
        {
            if (current is ServiceTokenHandler)
            {
                found = true;
                break;
            }
            current = dh.InnerHandler!;
        }

        found.Should().BeTrue(
            because: "AddServiceToken should attach ServiceTokenHandler to the typed client's pipeline; " +
                     "otherwise the Bearer header never gets stamped on outgoing calls.");
    }
}
