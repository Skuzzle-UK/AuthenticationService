using AuthenticationService.Services.HealthChecks;
using AuthenticationService.Storage;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AuthenticationService.Tests.Services.HealthChecks;

/// <summary>
/// Opens the raw DbConnection with a 2-second timeout to bypass the B1 retry strategy
/// that would otherwise stretch a stalled probe to ~150s. Covers open-success,
/// already-open short-circuit, and outer-cancellation paths. ("Open throws" is a
/// sub-case of the cancellation path — both end up in the same catch.)
/// </summary>
public class MySqlHealthCheckTests : IDisposable
{
    private readonly List<SqliteConnection> _connections = new();
    private readonly List<DatabaseContext> _contexts = new();

    public void Dispose()
    {
        foreach (var c in _contexts) c.Dispose();
        foreach (var c in _connections) c.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task CheckHealth_OpenSucceeds_ReturnsHealthy()
    {
        // arrange
        var (db, _) = BuildDbContext();
        var check = new MySqlHealthCheck(db);

        // act
        var result = await check.CheckHealthAsync(new HealthCheckContext());

        // assert
        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Be("MySQL reachable.");
    }

    [Fact]
    public async Task CheckHealth_OuterCancellationTokenAlreadyCancelled_ReturnsUnhealthy()
    {
        // arrange — pre-cancelled token must surface as Unhealthy rather than propagating;
        // otherwise the probe pipeline crashes.
        var (db, _) = BuildDbContext();
        var check = new MySqlHealthCheck(db);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // act
        var result = await check.CheckHealthAsync(new HealthCheckContext(), cts.Token);

        // assert
        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task CheckHealth_ConnectionAlreadyOpen_ReturnsHealthyWithoutClosing()
    {
        // arrange — pre-open the connection (simulating "earlier operation in this scope left it open").
        // The check should report Healthy AND must not close the still-in-use connection.
        var (db, connection) = BuildDbContext();
        await connection.OpenAsync();
        var check = new MySqlHealthCheck(db);

        // act
        var result = await check.CheckHealthAsync(new HealthCheckContext());

        // assert
        result.Status.Should().Be(HealthStatus.Healthy);
        connection.State.Should().Be(System.Data.ConnectionState.Open);
    }

    private (DatabaseContext db, SqliteConnection connection) BuildDbContext()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        var options = new DbContextOptionsBuilder<DatabaseContext>()
            .UseSqlite(connection)
            .Options;

        var db = new TestDatabaseContext(options);
        db.Database.EnsureCreated();
        _contexts.Add(db);

        // Close so the check's "is it open?" branch isn't accidentally short-circuited
        // (most tests expect to exercise the "open it ourselves" path).
        connection.Close();

        return (db, connection);
    }
}
