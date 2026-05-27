using AuthenticationService.Entities;
using AuthenticationService.Services.Hosted;
using AuthenticationService.Storage;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace AuthenticationService.Tests.Services.Hosted;

/// <summary>
/// Drives <c>RefreshAsync</c> directly (exposed internal) without the periodic timer.
/// Covers happy-path count + survival on a thrown scope so the timer loop survives.
/// </summary>
public class UserGaugeRefreshServiceTests : IDisposable
{
    private readonly List<SqliteConnection> _connections = [];
    private readonly List<DatabaseContext> _contexts = [];
    private readonly List<ServiceProvider> _providers = [];

    public void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var c in _contexts) c.Dispose();
        foreach (var c in _connections) c.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task RefreshAsync_HappyPath_QueriesUsersAndDoesNotThrow()
    {
        // arrange — three users: one MFA-enabled, one locked, one neither.
        var (service, db) = BuildService();
        var now = DateTimeOffset.UtcNow;
        db.Users.AddRange(
            new User { Id = "u1", UserName = "alice", NormalizedUserName = "ALICE", Email = "a@x", NormalizedEmail = "A@X", TwoFactorEnabled = true },
            new User { Id = "u2", UserName = "bob", NormalizedUserName = "BOB", Email = "b@x", NormalizedEmail = "B@X", LockoutEnd = now.AddHours(1) },
            new User { Id = "u3", UserName = "carol", NormalizedUserName = "CAROL", Email = "c@x", NormalizedEmail = "C@X" });
        await db.SaveChangesAsync();

        // act
        var act = async () => await service.RefreshAsync(CancellationToken.None);

        // assert — the gauge updates are observed via OTel meters (no easy hook); the
        // contract this test pins is "the query path runs without throwing against a
        // real DbContext." A regression here is usually a translation failure.
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RefreshAsync_WhenBodyThrows_SwallowsAndDoesNotPropagate()
    {
        // arrange — scope factory throws, simulating a transient DB / DI failure.
        // The worker must NOT propagate, or the outer timer loop dies and the gauges
        // freeze on stale values until the pod restarts.
        var scopeFactory = Substitute.For<IServiceScopeFactory>();
        scopeFactory.CreateScope().Returns<IServiceScope>(_ => throw new InvalidOperationException("kaboom"));

        var service = new UserGaugeRefreshService(
            NullLogger<UserGaugeRefreshService>.Instance,
            scopeFactory,
            TestMetricsFactory.Create());

        // act + assert
        var act = async () => await service.RefreshAsync(CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RefreshAsync_PreCancelledToken_DoesNotThrow()
    {
        // arrange — a cancelled token surfaces as OperationCanceledException inside the
        // EF query and is caught by the worker's generic catch. Pre-M5 / pre-tests this
        // would have torn down the timer; the contract is "cancellation is benign."
        var (service, _) = BuildService();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // act + assert
        var act = async () => await service.RefreshAsync(cts.Token);

        await act.Should().NotThrowAsync();
    }

    private (UserGaugeRefreshService service, DatabaseContext db) BuildService()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        var dbOptions = new DbContextOptionsBuilder<DatabaseContext>().UseSqlite(connection).Options;
        var db = new TestDatabaseContext(dbOptions);
        db.Database.EnsureCreated();
        _contexts.Add(db);

        var services = new ServiceCollection();
        services.AddDbContext<DatabaseContext, TestDatabaseContext>(opt => opt.UseSqlite(connection));
        var sp = services.BuildServiceProvider();
        _providers.Add(sp);

        var service = new UserGaugeRefreshService(
            NullLogger<UserGaugeRefreshService>.Instance,
            sp.GetRequiredService<IServiceScopeFactory>(),
            TestMetricsFactory.Create());

        return (service, db);
    }
}
