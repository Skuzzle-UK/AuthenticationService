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
    /// Args passed to the AppHost when the test fixture boots it. Default disables both
    /// HTTPS redirection (via <c>--integration-test</c> — required for tests to work over
    /// HTTP, sidesteps the Linux dev-cert dance) and the rate limiter (via
    /// <c>--rate-limiting-disabled</c> — so back-to-back scenario calls don't trip the
    /// global 4/10s cap). Subclasses can override to keep rate limiting on; the
    /// <c>--integration-test</c> flag is universally needed.
    /// </summary>
    protected virtual string[] AppHostArgs => ["--integration-test", "--rate-limiting-disabled"];

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
        using var client = App.CreateHttpClient("auth", "http");
        // Per-request timeout shorter than the deadline so a single hung probe doesn't
        // burn the whole wait budget — useful when the readyz health-check stalls on
        // a slow dependency (DB or Redis) rather than returning a quick 503.
        client.Timeout = TimeSpan.FromSeconds(5);
        var deadline = DateTime.UtcNow.AddSeconds(120);
        string lastResponse = "no response yet";

        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var response = await client.GetAsync("/readyz");
                lastResponse = $"{(int)response.StatusCode} {response.StatusCode}";
                if (response.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (Exception ex)
            {
                lastResponse = $"{ex.GetType().Name}: {ex.Message}";
            }
            await Task.Delay(500);
        }

        throw new InvalidOperationException(
            $"Auth service didn't become ready within 120s. Last /readyz response: {lastResponse}.");
    }
}