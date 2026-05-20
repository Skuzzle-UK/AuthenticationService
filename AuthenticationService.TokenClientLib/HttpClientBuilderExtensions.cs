using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Attaches the auth-service-token <see cref="DelegatingHandler"/> to a typed
/// <see cref="HttpClient"/> registration. Counterpart of
/// <c>services.AddAuthenticationServiceTokenClient(...)</c>: that wires the provider
/// + config; this binds a specific (audience, scopes) tuple to a specific HttpClient.
///
/// <para>Typical usage:</para>
/// <code>
/// services.AddAuthenticationServiceTokenClient(config.GetSection("AuthenticationService"));
///
/// services.AddHttpClient&lt;InventoryClient&gt;(c => c.BaseAddress = inventoryBaseUrl)
///         .AddServiceToken("inventory-api", "inventory.read");
/// </code>
///
/// <para>Every call through the resulting <c>HttpClient</c> arrives at the downstream
/// service carrying a fresh <c>Authorization: Bearer &lt;token&gt;</c> header.</para>
/// </summary>
public static class HttpClientBuilderExtensions
{
    /// <summary>
    /// Adds a <see cref="ServiceTokenHandler"/> to the typed-client's pipeline.
    /// Audience + scopes are baked in here — a typed client that calls a different
    /// audience or needs different scopes registers as a separate typed client.
    /// </summary>
    /// <param name="builder">The <see cref="IHttpClientBuilder"/> returned by <c>AddHttpClient</c>.</param>
    /// <param name="audience">Per-service audience for the token (e.g. <c>inventory-api</c>).</param>
    /// <param name="scopes">Scopes to request. Pass as <c>params</c> for ergonomics; the handler stores them as a read-only list.</param>
    public static IHttpClientBuilder AddServiceToken(
        this IHttpClientBuilder builder,
        string audience,
        params string[] scopes)
    {
        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new ArgumentException("audience must be a non-empty string.", nameof(audience));
        }
        if (scopes.Length == 0)
        {
            throw new ArgumentException("at least one scope must be supplied.", nameof(scopes));
        }

        builder.AddHttpMessageHandler(sp =>
        {
            var provider = sp.GetRequiredService<IServiceTokenProvider>();
            return new ServiceTokenHandler(provider, audience, scopes);
        });

        return builder;
    }
}
