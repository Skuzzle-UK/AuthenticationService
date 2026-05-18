using System.Diagnostics.Metrics;
using AuthenticationService.Observability;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationService.Tests.Helpers;

/// <summary>
/// Creates a real <see cref="AuthMetrics"/> backed by the framework's default
/// <see cref="IMeterFactory"/>. The meters fire into a Meter that isn't observed
/// by anything in the test process, so calls are effectively no-ops — but the
/// metric methods exercise their full implementation path, which is what we
/// want for unit tests (catches "tag value blew up cardinality" type bugs).
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
