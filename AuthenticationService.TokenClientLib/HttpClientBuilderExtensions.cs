using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationService.TokenClientLib;

/// <summary>
/// Binds a <see cref="ServiceTokenHandler"/> to a typed <see cref="HttpClient"/> so
/// every call carries a fresh <c>Authorization: Bearer &lt;token&gt;</c> header.
/// <example>
/// <code>
/// services.AddAuthenticationServiceTokenClient(config.GetSection("AuthenticationService"));
///
/// services.AddHttpClient&lt;InventoryClient&gt;(c => c.BaseAddress = inventoryBaseUrl)
///         .AddServiceToken("inventory-api", "inventory.read");
/// </code>
/// </example>
/// </summary>
public static class HttpClientBuilderExtensions
{
    /// <summary>
    /// Adds a <see cref="ServiceTokenHandler"/> to the typed-client's pipeline. Audience
    /// + scopes are baked in — a client calling a different audience or needing different
    /// scopes registers as a separate typed client.
    /// </summary>
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
