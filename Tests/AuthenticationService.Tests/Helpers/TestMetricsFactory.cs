using System.Diagnostics.Metrics;
using AuthenticationService.Observability;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationService.Tests.Helpers;

/// <summary>
/// Builds a real <see cref="AuthMetrics"/> against an unobserved Meter — calls are no-ops but exercise
/// their full implementation path (catches tag-cardinality bugs).
/// </summary>
internal static class TestMetricsFactory
{
    public static AuthMetrics Create()
    {
        var services = new ServiceCollection();
        services.AddMetrics();
        var provider = services.BuildServiceProvider();
        return new AuthMetrics(provider.GetRequiredService<IMeterFactory>());
    }
}
