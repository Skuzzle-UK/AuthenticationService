using AwesomeAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// <para>This is the one-line API consumers call per outgoing-service-call typed client:</para>
/// <code>services.AddHttpClient&lt;InventoryClient&gt;().AddServiceToken("inventory-api", "inventory.read");</code>
///
/// <para>Two things matter:</para>
/// <list type="bullet">
///   <item><description>Bad arguments are rejected loudly. <c>audience</c> = whitespace or no scopes is a config bug that would only surface at the first outgoing call — much better to fail at registration time.</description></item>
///   <item><description>The handler that lands in the typed client's pipeline is a fully-constructed <see cref="ServiceTokenHandler"/>, pulled from the DI container with a real <see cref="IServiceTokenProvider"/> attached. Otherwise we've just registered nothing useful.</description></item>
/// </list>
/// </summary>
public class HttpClientBuilderExtensionsTests
{
    [Fact]
    public void AddServiceToken_EmptyAudience_Throws()
    {
        // arrange
        var services = new ServiceCollection();
        var builder = services.AddHttpClient("test-client");

        // act
        var act = () => builder.AddServiceToken(audience: "  ", scopes: "any.scope");

        // assert — the message names the failing argument so an operator can fix it.
        act.Should().Throw<ArgumentException>().WithMessage("*audience*");
    }

    [Fact]
    public void AddServiceToken_NoScopes_Throws()
    {
        // arrange
        var services = new ServiceCollection();
        var builder = services.AddHttpClient("test-client");

        // act
        var act = () => builder.AddServiceToken(audience: "inventory-api");

        // assert — every service token needs at least one scope; a no-scope token has no purpose.
        act.Should().Throw<ArgumentException>().WithMessage("*scope*");
    }

    [Fact]
    public void AddServiceToken_RegistersServiceTokenHandlerInTheTypedClientPipeline()
    {
        // arrange — wire up the typed-client side with a substituted provider so we don't need
        // a live auth server to construct the handler chain.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Substitute.For<IServiceTokenProvider>());
        services.AddHttpClient("test-client").AddServiceToken("inventory-api", "inventory.read");

        using var sp = services.BuildServiceProvider();

        // act — build the actual HttpClient the consumer would receive at injection time. If
        // the handler weren't registered, this would still succeed but the pipeline wouldn't
        // contain ServiceTokenHandler. We assert on the live pipeline shape via the typed-client
        // factory's IHttpMessageHandlerFactory — it builds the full chain on demand.
        var handlerFactory = sp.GetRequiredService<IHttpMessageHandlerFactory>();
        using var handler = handlerFactory.CreateHandler("test-client");

        // Walk down the DelegatingHandler chain; assert ServiceTokenHandler is present.
        // The framework wraps everything in a LifetimeTrackingHttpMessageHandler so we don't
        // pattern-match the root — we walk InnerHandler links.
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

        // assert — without the registration this would loop straight past to the primary handler.
        found.Should().BeTrue(
            because: "AddServiceToken should attach ServiceTokenHandler to the typed client's pipeline; " +
                     "otherwise the Bearer header never gets stamped on outgoing calls.");
    }
}
