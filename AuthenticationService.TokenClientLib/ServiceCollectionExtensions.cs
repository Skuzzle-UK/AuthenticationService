using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Registration entry point for the outgoing service-token plumbing — the consumer
/// side of OAuth client-credentials. Pair with
/// <see cref="HttpClientBuilderExtensions.AddServiceToken"/> on each typed
/// <see cref="HttpClient"/> that needs auto-stamped Bearer headers.
///
/// <para>Sibling library: <c>AuthenticationService.TokenValidationLib</c> handles
/// <em>incoming</em> JWTs (JwtBearer + scope policies). The two halves are orthogonal
/// — a service might validate incoming tokens without calling out, or call out
/// without validating anything — so they're separate NuGets.</para>
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the outgoing-token plumbing for service-to-service calls. After
    /// this, register typed HttpClients with <c>.AddServiceToken(audience, scopes)</c>
    /// to get auto-stamped Bearer headers.
    ///
    /// <para>By convention this binds against the same <c>"AuthenticationService"</c>
    /// configuration section the validation lib uses — the <c>Authority</c> field is
    /// shared, plus this looks for <c>ClientId</c> / <c>ClientSecret</c> in the same
    /// section.</para>
    /// </summary>
    public static IServiceCollection AddAuthenticationServiceTokenClient(
        this IServiceCollection services,
        IConfiguration configurationSection)
    {
        services.AddOptions<ServiceTokenClientOptions>()
            .Bind(configurationSection)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // Named HttpClient — used by the provider for both discovery + token requests.
        // Goes through IHttpClientFactory so connection-pool / DNS-refresh semantics
        // are right (a long-lived singleton with a captive HttpClient would miss
        // those).
        services.AddHttpClient(ServiceTokenProvider.HttpClientName, http =>
        {
            http.Timeout = TimeSpan.FromSeconds(30);
        });

        // Provider must be a singleton — the cache + per-key semaphores need to be
        // shared across every caller in the process. A scoped/transient lifetime
        // would mean a fresh cache per request, defeating the whole point.
        services.AddSingleton<IServiceTokenProvider, ServiceTokenProvider>();

        return services;
    }
}
