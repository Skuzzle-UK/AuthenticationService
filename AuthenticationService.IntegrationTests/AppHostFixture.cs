using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthenticationService.IntegrationTests;

/// <summary>
/// Custom logger provider that captures auth-resource log messages into the fixture's
/// buffer. Aspire forwards each project resource's stdout/stderr to MEL under category
/// <c>AuthenticationService.AppHost.Resources.&lt;resource-name&gt;</c> — hooking it here
/// is the most reliable way to get auth's startup logs out of the testing harness when
/// <c>ResourceLoggerService.WatchAsync</c> doesn't flush in time.
/// </summary>
internal sealed class AuthLogCaptureProvider(Action<string, LogLevel, string> sink) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, sink);

    public void Dispose() { }

    private sealed class CapturingLogger(string category, Action<string, LogLevel, string> sink) : ILogger
    {
        // Only care about Aspire's per-resource categories.
        private static bool IsResourceCategory(string c) =>
            c.StartsWith("AuthenticationService.AppHost.Resources.", StringComparison.Ordinal);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => IsResourceCategory(category) && logLevel != LogLevel.None;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var msg = formatter(state, exception);
            if (exception is not null) msg += " :: " + exception;
            sink(category, logLevel, msg);
        }
    }
}

/// <summary>
/// Boots the entire Aspire AppHost graph (auth project + DB + Redis + smtp4dev) once per
/// test run. Container start-up is ~30s on cold pull (longer for SQL Server); shared
/// across every test class via <see cref="IntegrationTestCollection"/>. Tests isolate via
/// unique data (random emails) since they share one DB.
///
/// Database provider defaults to MySQL. Set <c>INTEGRATION_DB_PROVIDER</c> env var
/// (<c>"MySQL"</c>, <c>"SqlServer"</c>, or <c>"PostgreSQL"</c>) before running to swap.
/// The AppHost reads the env var from this process's environment.
/// </summary>
public class AppHostFixture : IAsyncLifetime
{
    private DistributedApplication? _app;
    private readonly List<string> _authLogBuffer = new();
    private readonly object _authLogLock = new();

    public DistributedApplication App => _app
        ?? throw new InvalidOperationException("Fixture not initialised — InitializeAsync didn't run.");

    /// <summary>
    /// The DB provider the harness booted against — driven by <c>INTEGRATION_DB_PROVIDER</c>,
    /// defaults to <c>"MySQL"</c>. Surface so scenario tests can branch on it when a
    /// provider-specific edge case needs verification. Provider-pinned subclasses
    /// (e.g. <see cref="QuirksFixtures.MySqlAppHostFixture"/>) override this so the
    /// in-process multi-provider quirks suite doesn't depend on the env var.
    /// </summary>
    public virtual string DbProvider =>
        Environment.GetEnvironmentVariable("INTEGRATION_DB_PROVIDER") is { Length: > 0 } p
            ? p
            : "MySQL";

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

        builder.Services.AddLogging(logging =>
        {
            // Information so our custom provider sees the lines Aspire forwards under
            // "AuthenticationService.AppHost.Resources.*" — these are at Information.
            logging.SetMinimumLevel(LogLevel.Information);
            logging.AddProvider(new AuthLogCaptureProvider((category, level, message) =>
            {
                var resource = category["AuthenticationService.AppHost.Resources.".Length..];
                // Only capture the auth resource. SqlServer / Postgres / Redis startup
                // chatter is voluminous and would push auth's own logs out of any
                // bounded buffer — and it's the auth logs we actually need to see
                // when diagnosing why auth crashed.
                if (!resource.StartsWith("auth", StringComparison.Ordinal)) return;
                lock (_authLogLock)
                {
                    _authLogBuffer.Add($"    [{resource}/{level}] {message}");
                    if (_authLogBuffer.Count > 500)
                    {
                        _authLogBuffer.RemoveRange(0, _authLogBuffer.Count - 500);
                    }
                }
            }));
        });

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

    /// <summary>
    /// Total budget for the auth service to come up after containers start. Bumped
    /// for SqlServer / Postgres on cold image pulls — they're noticeably slower to
    /// reach a serving state than MySQL.
    /// </summary>
    protected virtual TimeSpan ReadinessDeadline => TimeSpan.FromSeconds(300);

    private async Task WaitForAuthServiceReadyAsync()
    {
        // Phase 1: wait for the auth resource itself to transition to Running. Aspire's
        // ResourceNotifications is the canonical source of truth for resource lifecycle
        // — a probe-based wait can't distinguish "process not started yet" from "process
        // started but slow to respond." This times out cleanly with the resource's
        // current state if startup is genuinely broken.
        using var resourceCts = new CancellationTokenSource(ReadinessDeadline);
        try
        {
            await App.ResourceNotifications.WaitForResourceAsync(
                "auth",
                KnownResourceStates.Running,
                resourceCts.Token);
        }
        catch (OperationCanceledException)
        {
            var snapshot = await CaptureResourceSnapshotAsync();
            throw new InvalidOperationException(
                $"'auth' resource didn't reach 'Running' state within {ReadinessDeadline.TotalSeconds}s. "
                + $"Resource snapshot at timeout:\n{snapshot}");
        }

        // Phase 2: now that auth is Running, poll /readyz so we know the HTTP pipeline
        // is up AND health checks (DB + Redis) pass. Migrations might still be applying
        // here so probes can take a few seconds — 15s per-request timeout is generous.
        using var client = App.CreateHttpClient("auth", "http");
        client.Timeout = TimeSpan.FromSeconds(15);
        var deadline = DateTime.UtcNow.Add(ReadinessDeadline);
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

        var endSnapshot = await CaptureResourceSnapshotAsync();
        throw new InvalidOperationException(
            $"Auth service was Running but didn't pass /readyz within {ReadinessDeadline.TotalSeconds}s. "
            + $"Last /readyz response: {lastResponse}.\nResource snapshot:\n{endSnapshot}");
    }

    /// <summary>
    /// Snapshot every resource's current state for diagnostic output on timeout. Names
    /// + states + health-check status so a failed test gives an actionable trace instead
    /// of just "didn't come up."
    /// </summary>
    private async Task<string> CaptureResourceSnapshotAsync()
    {
        var lines = new List<string>();
        try
        {
            await foreach (var ev in App.ResourceNotifications.WatchAsync(CancellationToken.None)
                .WithCancellation(new CancellationTokenSource(TimeSpan.FromSeconds(2)).Token))
            {
                var snap = ev.Snapshot;
                var health = snap.HealthStatus?.ToString() ?? "n/a";
                var exitCode = snap.ExitCode is { } code ? $", exit={code}" : string.Empty;
                lines.Add($"  - {ev.Resource.Name}: state={snap.State?.Text ?? "?"}, health={health}{exitCode}");
                if (lines.Count > 20) break;
            }
        }
        catch (OperationCanceledException)
        {
            // Expected — we hard-stop the stream after the snapshot window elapses.
        }
        catch (Exception ex)
        {
            lines.Add($"  [snapshot capture failed: {ex.GetType().Name}: {ex.Message}]");
        }

        // Tail of auth's recent logs — far more useful than just state when the service
        // crashed during startup. IResourceLoggerService is the canonical Aspire API for
        // resource stdout/stderr.
        var authLog = await CaptureAuthLogTailAsync(lineLimit: 80);
        lines.Add(string.Empty);
        lines.Add("auth resource logs (tail):");
        lines.Add(authLog);

        return lines.Count == 0 ? "  (no resource events captured)" : string.Join("\n", lines);
    }

    private Task<string> CaptureAuthLogTailAsync(int lineLimit)
    {
        lock (_authLogLock)
        {
            if (_authLogBuffer.Count == 0)
            {
                return Task.FromResult("    (no log entries captured — log tail may not have started yet)");
            }
            var start = Math.Max(0, _authLogBuffer.Count - lineLimit);
            var snapshot = _authLogBuffer.GetRange(start, _authLogBuffer.Count - start);
            return Task.FromResult(string.Join("\n", snapshot));
        }
    }
}