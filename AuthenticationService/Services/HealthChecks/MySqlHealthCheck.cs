using System.Data;
using System.Data.Common;
using AuthenticationService.Storage;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AuthenticationService.Services.HealthChecks;

/// <summary>
/// Readiness probe for MySQL. Opens the underlying <see cref="DbConnection"/> directly
/// with a hard timeout — bypasses EF's execution strategy so a stalled DB can't extend
/// the probe by the retry budget (5 attempts × 30s backoff cap with the retry strategy
/// from B1). K8s would pull the pod from the LB during the wait, draining capacity
/// while every replica probes the same slow DB.
/// </summary>
public class MySqlHealthCheck : IHealthCheck
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);

    private readonly DatabaseContext _db;

    public MySqlHealthCheck(DatabaseContext db)
    {
        _db = db;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var conn = _db.Database.GetDbConnection();

        // Already open from earlier in this scope — connection is alive, don't touch it.
        if (conn.State == ConnectionState.Open)
        {
            return HealthCheckResult.Healthy("MySQL reachable.");
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(ConnectTimeout);

        try
        {
            await conn.OpenAsync(cts.Token);
            return HealthCheckResult.Healthy("MySQL reachable.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("MySQL unreachable.", ex);
        }
        finally
        {
            // We opened it, we close it — don't leak a connection to the pool in
            // mid-operation state.
            if (conn.State == ConnectionState.Open)
            {
                try { await conn.CloseAsync(); } catch { /* swallow — already reporting health */ }
            }
        }
    }
}
