using AuthenticationService.Entities;
using AuthenticationService.Services.Hosted;
using AuthenticationService.Settings;
using AuthenticationService.Storage;
using AwesomeAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Services.Hosted;

/// <summary>
/// Drives <c>RunCleanupAsync</c> directly (exposed internal) without the periodic timer.
/// Covers audit-row TTL, expired RevokedToken removal, expired RefreshToken removal, empty-db no-op.
/// </summary>
public class DataRetentionCleanupServiceTests : IDisposable
{
    private readonly List<SqliteConnection> _connections = new();
    private readonly List<DatabaseContext> _contexts = new();
    private readonly List<ServiceProvider> _providers = new();

    public void Dispose()
    {
        foreach (var p in _providers) p.Dispose();
        foreach (var c in _contexts) c.Dispose();
        foreach (var c in _connections) c.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task RunCleanup_DeletesAuditRowsPastTTL_KeepsRecentOnes()
    {
        // arrange — TTL = 90 days. Three rows: 100 days (delete), 30 days (keep), 1 hour (keep).
        var (service, db) = BuildService(retentionTtlDays: 90);
        var seedUser = new User { Id = "u1", UserName = "alice", Email = "a@b.c", NormalizedEmail = "A@B.C", NormalizedUserName = "ALICE" };
        db.Users.Add(seedUser);
        db.RevokedTokenAccessAttempts.AddRange(
            new RevokedTokenAccessAttempt { TokenJti = "j1", UserId = "u1", IpAddress = "1.1.1.1", CreatedAt = DateTime.UtcNow.AddDays(-100) },
            new RevokedTokenAccessAttempt { TokenJti = "j2", UserId = "u1", IpAddress = "1.1.1.1", CreatedAt = DateTime.UtcNow.AddDays(-30) },
            new RevokedTokenAccessAttempt { TokenJti = "j3", UserId = "u1", IpAddress = "1.1.1.1", CreatedAt = DateTime.UtcNow.AddHours(-1) });
        await db.SaveChangesAsync();

        // act
        await service.RunCleanupAsync(CancellationToken.None);

        // assert
        db.ChangeTracker.Clear();
        var remaining = await db.RevokedTokenAccessAttempts.OrderBy(x => x.CreatedAt).ToListAsync();
        remaining.Should().HaveCount(2);
        remaining.Select(r => r.TokenJti).Should().BeEquivalentTo(new[] { "j2", "j3" });
    }

    [Fact]
    public async Task RunCleanup_DeletesExpiredRevokedTokens_KeepsLiveOnes()
    {
        // arrange
        var (service, db) = BuildService();
        db.RevokedTokens.AddRange(
            new RevokedToken { TokenJti = "expired", UserId = "u1", ExpiresAt = DateTime.UtcNow.AddMinutes(-1) },
            new RevokedToken { TokenJti = "live", UserId = "u1", ExpiresAt = DateTime.UtcNow.AddMinutes(5) });
        await db.SaveChangesAsync();

        // act
        await service.RunCleanupAsync(CancellationToken.None);

        // assert
        db.ChangeTracker.Clear();
        (await db.RevokedTokens.Select(t => t.TokenJti).ToListAsync())
            .Should().BeEquivalentTo(new[] { "live" });
    }

    [Fact]
    public async Task RunCleanup_DeletesExpiredRefreshTokens()
    {
        // arrange
        var (service, db) = BuildService();
        db.Users.Add(new User { Id = "u1", UserName = "u", Email = "u@u", NormalizedEmail = "U@U", NormalizedUserName = "U" });
        db.RefreshTokens.AddRange(
            new RefreshToken
            {
                Id = Guid.NewGuid(), UserId = "u1", TokenHash = "hash-expired",
                FamilyId = Guid.NewGuid(), CreatedAt = DateTime.UtcNow.AddDays(-30),
                ExpiresAt = DateTime.UtcNow.AddDays(-1),
            },
            new RefreshToken
            {
                Id = Guid.NewGuid(), UserId = "u1", TokenHash = "hash-live",
                FamilyId = Guid.NewGuid(), CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
            });
        await db.SaveChangesAsync();

        // act
        await service.RunCleanupAsync(CancellationToken.None);

        // assert
        db.ChangeTracker.Clear();
        (await db.RefreshTokens.Select(t => t.TokenHash).ToListAsync())
            .Should().BeEquivalentTo(new[] { "hash-live" });
    }

    [Fact]
    public async Task RunCleanup_EmptyDatabase_NoOpNoException()
    {
        // arrange
        var (service, _) = BuildService();

        // act + assert
        var act = async () => await service.RunCleanupAsync(CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task RunCleanup_WhenBodyThrows_SwallowsAndDoesNotPropagate()
    {
        // arrange
        var scopeFactory = Substitute.For<IServiceScopeFactory>();
        scopeFactory.CreateScope().Returns<IServiceScope>(_ => throw new InvalidOperationException("kaboom"));

        var service = new DataRetentionCleanupService(
            NullLogger<DataRetentionCleanupService>.Instance,
            scopeFactory,
            Options.Create(new DataRetentionSettings { CleanupIntervalInHours = 12, RevokedReplayTTLInDays = 90 }));

        // act + assert
        var act = async () => await service.RunCleanupAsync(CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    private (DataRetentionCleanupService service, DatabaseContext db) BuildService(double retentionTtlDays = 90)
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        var dbOptions = new DbContextOptionsBuilder<DatabaseContext>().UseSqlite(connection).Options;
        var db = new DatabaseContext(dbOptions);
        db.Database.EnsureCreated();
        _contexts.Add(db);

        // Real ServiceProvider so the service's CreateScope().GetRequiredService<DatabaseContext>() resolves to our context.
        var services = new ServiceCollection();
        services.AddDbContext<DatabaseContext>(opt => opt.UseSqlite(connection));
        var sp = services.BuildServiceProvider();
        _providers.Add(sp);

        var service = new DataRetentionCleanupService(
            NullLogger<DataRetentionCleanupService>.Instance,
            sp.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new DataRetentionSettings
            {
                CleanupIntervalInHours = 12,
                RevokedReplayTTLInDays = retentionTtlDays,
            }));

        return (service, db);
    }
}
