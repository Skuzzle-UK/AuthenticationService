using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Skuzzle.Core.Authentication.Client.Settings;

namespace Skuzzle.Core.Authentication.Client;

public static class HostExtensions
{
    public static IServiceCollection AddAuthenticationServices(this IServiceCollection services, IConfiguration configuration) =>
        services
            .AddHttpClient()
            .AddMemoryCache()
            .Configure<AuthenticationClientSettings>(configuration.GetSection(nameof(AuthenticationClientSettings)))
            .AddScoped<IAuthenticationClient, AuthenticationClient>();
}
