using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

namespace AuthenticationService.AppHost;

/// <summary>
/// Posts the "Auth Service Overview" dashboard to the grafana/otel-lgtm container
/// via its HTTP API once the container reports ready. Avoids the Windows + Docker
/// single-file bind-mount bug that blocks the cleaner file-based provisioning route.
///
/// <para>Idempotent — uses <c>overwrite: true</c> on the import, so re-runs after
/// hot-reload or restart just update the existing dashboard. Survives container
/// restarts because Grafana persists imported dashboards in its internal SQLite DB
/// inside the container; only a full <c>docker rm</c> of the container loses them,
/// in which case the next AppHost run re-imports.</para>
/// </summary>
internal static class GrafanaDashboardProvisioner
{
    private const string AdminUser = "admin";
    private const string AdminPassword = "admin";
    private static readonly TimeSpan HealthPollInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan HealthPollTimeout = TimeSpan.FromMinutes(2);

    public static async Task ImportDashboardAsync(
        string grafanaBaseUrl,
        string dashboardJsonPath,
        ILogger logger,
        CancellationToken ct)
    {
        if (!File.Exists(dashboardJsonPath))
        {
            logger.LogWarning(
                "Grafana dashboard JSON not found at {Path}; skipping auto-import.",
                dashboardJsonPath);
            return;
        }

        using var http = new HttpClient { BaseAddress = new Uri(grafanaBaseUrl) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{AdminUser}:{AdminPassword}")));

        if (!await WaitForGrafanaReadyAsync(http, logger, ct))
        {
            logger.LogWarning(
                "Grafana didn't respond healthy within {Timeout}s; skipping dashboard import.",
                HealthPollTimeout.TotalSeconds);
            return;
        }

        try
        {
            var dashboardJson = await File.ReadAllTextAsync(dashboardJsonPath, ct);
            var dashboardNode = JsonNode.Parse(dashboardJson)
                ?? throw new InvalidOperationException($"Dashboard JSON at {dashboardJsonPath} parsed as null.");

            // Wipe id/version so Grafana treats this as a fresh import each time —
            // otherwise the server-side version may not match what we hold and we'd
            // get a 412 Precondition Failed.
            if (dashboardNode is JsonObject obj)
            {
                obj.Remove("id");
                obj.Remove("version");
            }

            var payload = new JsonObject
            {
                ["dashboard"] = dashboardNode,
                ["overwrite"] = true,
                ["message"] = "Auto-imported by AuthenticationService.AppHost on container ready"
            };

            var resp = await http.PostAsJsonAsync("/api/dashboards/db", payload, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);

            if (!resp.IsSuccessStatusCode)
            {
                logger.LogWarning(
                    "Grafana dashboard import returned {StatusCode}: {Body}",
                    (int)resp.StatusCode,
                    body);
                return;
            }

            logger.LogInformation(
                "Auth Service Overview dashboard imported into Grafana at {Url}. Response: {Body}",
                grafanaBaseUrl,
                body);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Grafana dashboard import failed: {Message}", ex.Message);
        }
    }

    private static async Task<bool> WaitForGrafanaReadyAsync(
        HttpClient http,
        ILogger logger,
        CancellationToken ct)
    {
        // Grafana's /api/health returns 200 once the HTTP server is up. The LGTM
        // container also runs Prometheus / Tempo / Loki — they take a few extra
        // seconds to fully initialise but we only need Grafana itself for the
        // dashboard import.
        var deadline = DateTime.UtcNow + HealthPollTimeout;
        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            try
            {
                var resp = await http.GetAsync("/api/health", ct);
                if (resp.IsSuccessStatusCode)
                {
                    logger.LogInformation("Grafana healthy at {BaseAddress}.", http.BaseAddress);
                    return true;
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                // Connection refused / timeout — container still starting. Retry.
            }
            await Task.Delay(HealthPollInterval, ct);
        }
        return false;
    }
}
