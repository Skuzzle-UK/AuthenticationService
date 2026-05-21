using Aspire.Hosting;
using Aspire.Hosting.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Boots the entire Aspire AppHost graph (auth project + MySQL + Redis + smtp4dev)
/// once per test run. Container start-up is ~30s on cold pull; shared across every test
/// class via <see cref="IntegrationTestCollection"/>. Tests isolate via unique data
/// (random emails) since they share one MySQL.
/// </summary>
public class AppHostFixture : IAsyncLifetime
{
    private DistributedApplication? _app;

    public DistributedApplication App => _app
        ?? throw new InvalidOperationException("Fixture not initialised — InitializeAsync didn't run.");

    /// <summary>
    /// Args passed to the AppHost. <c>--integration-test</c> disables HTTPS redirection
    /// (so tests can hit HTTP, sidesteps the Linux dev-cert dance) and is universally
    /// required. <c>--rate-limiting-disabled</c> turns off the 4/10s cap so back-to-back
    /// scenario calls don't trip it; subclasses override to keep it on.
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
        // Per-request timeout shorter than the wait deadline — a stalled probe (slow
        // dependency that doesn't return a quick 503) mustn't burn the whole budget.
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