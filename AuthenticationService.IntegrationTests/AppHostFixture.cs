using Aspire.Hosting;
using Aspire.Hosting.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Boots the entire Aspire AppHost graph (auth project + MySQL + Redis + smtp4dev)
/// once per test run. Container start-up is the slow bit (~30s on cold pull); we share
/// across every test class via <see cref="IntegrationTestCollection"/>. Tests must
/// isolate themselves via unique data (random emails) since they share one MySQL.
///
/// <para>The default fixture passes <c>--integration-test</c> to the AppHost which
/// flips <c>HostingSettings:RateLimitingEnabled</c> to false — so a sequence of
/// credential calls across scenarios doesn't trip the global 4/10s cap. Subclasses
/// can override <see cref="AppHostArgs"/> to run with different host configuration
/// (see <see cref="RateLimitedAppHostFixture"/>).</para>
/// </summary>
public class AppHostFixture : IAsyncLifetime
{
    private DistributedApplication? _app;

    public DistributedApplication App => _app
        ?? throw new InvalidOperationException("Fixture not initialised — InitializeAsync didn't run.");

    /// <summary>
    /// Args passed to the AppHost when the test fixture boots it. Default disables rate
    /// limiting via the <c>--integration-test</c> flag the AppHost recognises. Override
    /// in a subclass to run with different host config — e.g., rate-limiting tests need
    /// the production-shape configuration where rate limiting is enabled.
    /// </summary>
    protected virtual string[] AppHostArgs => ["--integration-test"];

    public async Task InitializeAsync()
    {
        var builder = await DistributedApplicationTestingBuilder
            .CreateAsync<Projects.AuthenticationService_AppHost>(AppHostArgs);

        builder.Services.AddLogging(logging => logging.SetMinimumLevel(LogLevel.Warning));

        _app = await builder.BuildAsync();
        await _app.StartAsync();

        await WaitForAuthServiceReadyAsync();
    }

    public async Task DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    private async Task WaitForAuthServiceReadyAsync()
    {
        // Aspire's StartAsync returns when resources are launched, but the auth project
        // might still be running EF migrations + seeding the admin user. Polling /healthz
        // lets us proceed only when the service is truly ready to serve traffic.
        using var client = App.CreateHttpClient("auth", "https");
        var deadline = DateTime.UtcNow.AddSeconds(120);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var response = await client.GetAsync("/healthz");
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch
            {
                // Auth service still starting — keep polling.
            }
            await Task.Delay(500);
        }

        throw new InvalidOperationException(
            "Auth service didn't become ready within 120s. Check the auth resource's logs.");
    }
}