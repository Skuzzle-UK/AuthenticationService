using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Registration entry point for outgoing service-token plumbing (OAuth client-credentials).
/// Pair with <see cref="HttpClientBuilderExtensions.AddServiceToken"/> on each typed
/// <see cref="HttpClient"/> that needs auto-stamped Bearer headers.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the outgoing-token plumbing for service-to-service calls. Conventionally
    /// bound against the <c>"AuthenticationService"</c> config section, which carries
    /// <c>Authority</c>, <c>ClientId</c>, and <c>ClientSecret</c>.
    /// </summary>
    public static IServiceCollection AddAuthenticationServiceTokenClient(
        this IServiceCollection services,
        IConfiguration configurationSection)
    {
        services.AddOptions<ServiceTokenClientOptions>()
            .Bind(configurationSection)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // Through IHttpClientFactory so connection-pool / DNS-refresh semantics are
        // right — a long-lived singleton with a captive HttpClient would miss those.
        services.AddHttpClient(ServiceTokenProvider.HttpClientName, http =>
        {
            http.Timeout = TimeSpan.FromSeconds(30);
        });

        // Singleton: cache + per-key semaphores must be shared across the process.
        services.AddSingleton<IServiceTokenProvider, ServiceTokenProvider>();

        return services;
    }
}
