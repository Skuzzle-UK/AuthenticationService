using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Services.Hosted;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Storage;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Services.Hosted;

/// <summary>
/// Drives the threshold-escalation sweep directly. Covers no-op, warn, idempotent re-warn,
/// lock cascade, idempotent re-lock, missing user, email-send failure, orphan jti.
/// </summary>
public class RevokedTokenReplayEscalationServiceTests : IDisposable
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
    public async Task RunSweep_NoReplaysInWindow_NoOp()
    {
        // arrange
        var (service, db, deps) = BuildService();

        // act
        await service.RunSweepAsync(CancellationToken.None);

        // assert
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
        await deps.TokenService.DidNotReceive().RevokeAllRefreshTokenFamiliesAsync(
            Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task RunSweep_AttemptsAtWarnThreshold_StampsWarnedAtButDoesNotLock()
    {
        // arrange
        var (service, db, deps) = BuildService(warnThreshold: 2, lockThreshold: 5);
        var revokedToken = new RevokedToken { TokenJti = "j1", UserId = "u1", ExpiresAt = DateTime.UtcNow.AddMinutes(10) };
        db.RevokedTokens.Add(revokedToken);
        SeedAttempts(db, "j1", count: 2);
        await db.SaveChangesAsync();

        // act
        await service.RunSweepAsync(CancellationToken.None);

        // assert
        db.ChangeTracker.Clear();
        var stamped = await db.RevokedTokens.SingleAsync();
        stamped.WarnedAt.Should().NotBeNull(because: "warn threshold met — stamp the row.");
        stamped.LockedAt.Should().BeNull(because: "lock threshold not reached.");
        await deps.UserService.DidNotReceive().SetLockoutEndDateAsync(Arg.Any<User>(), Arg.Any<DateTimeOffset?>());
    }

    [Fact]
    public async Task RunSweep_AlreadyWarned_DoesNotRefireOnNextSweep()
    {
        // arrange — WarnedAt already populated; idempotent skip.
        var (service, db, deps) = BuildService(warnThreshold: 2, lockThreshold: 5);
        var revokedToken = new RevokedToken
        {
            TokenJti = "j1", UserId = "u1",
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
            WarnedAt = DateTime.UtcNow.AddMinutes(-1),
        };
        db.RevokedTokens.Add(revokedToken);
        SeedAttempts(db, "j1", count: 2);
        await db.SaveChangesAsync();

        var originalWarnedAt = revokedToken.WarnedAt.Value;

        // act
        await service.RunSweepAsync(CancellationToken.None);

        // assert
        db.ChangeTracker.Clear();
        (await db.RevokedTokens.SingleAsync()).WarnedAt
            .Should().BeCloseTo(originalWarnedAt, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task RunSweep_AttemptsAtLockThreshold_CascadesLockRevokeAndEmail()
    {
        // arrange
        var (service, db, deps) = BuildService(warnThreshold: 2, lockThreshold: 5);
        var user = new User { Id = "u1", UserName = "alice", Email = "alice@example.com" };
        db.Users.Add(user);
        db.RevokedTokens.Add(new RevokedToken { TokenJti = "j1", UserId = "u1", ExpiresAt = DateTime.UtcNow.AddMinutes(10) });
        SeedAttempts(db, "j1", count: 5);
        await db.SaveChangesAsync();

        deps.UserService.FindByIdAsync("u1").Returns(user);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("reset-tok");

        // act
        await service.RunSweepAsync(CancellationToken.None);

        // assert
        await deps.UserService.Received(1).SetLockoutEndDateAsync(user, LockoutDurations.Indefinite);
        await deps.TokenService.Received(1).RevokeAllRefreshTokenFamiliesAsync("u1", RevocationReasons.ReuseDetected);
        await deps.UserService.Received(1).UpdateSecurityStampAsync(user);
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com", EmailSubjects.SuspiciousActivity, Arg.Any<string>());

        db.ChangeTracker.Clear();
        var stamped = await db.RevokedTokens.SingleAsync();
        stamped.LockedAt.Should().NotBeNull();
        stamped.WarnedAt.Should().NotBeNull(
            because: "warn fires too because attemptCount >= warnThreshold; both stamps are recorded.");
    }

    [Fact]
    public async Task RunSweep_AlreadyLocked_DoesNotRefireCascade()
    {
        // arrange
        var (service, db, deps) = BuildService(warnThreshold: 2, lockThreshold: 5);
        db.RevokedTokens.Add(new RevokedToken
        {
            TokenJti = "j1", UserId = "u1",
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
            WarnedAt = DateTime.UtcNow.AddMinutes(-2),
            LockedAt = DateTime.UtcNow.AddMinutes(-1),
        });
        SeedAttempts(db, "j1", count: 10);
        await db.SaveChangesAsync();

        // act
        await service.RunSweepAsync(CancellationToken.None);

        // assert
        await deps.UserService.DidNotReceive().SetLockoutEndDateAsync(Arg.Any<User>(), Arg.Any<DateTimeOffset?>());
        await deps.TokenService.DidNotReceive().RevokeAllRefreshTokenFamiliesAsync(Arg.Any<string>(), Arg.Any<string>());
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task RunSweep_LockUserMissing_LogsAndSkipsCascade()
    {
        // arrange — user behind the revoked token has been deleted; log and continue rather than crash.
        var (service, db, deps) = BuildService(warnThreshold: 2, lockThreshold: 5);
        db.RevokedTokens.Add(new RevokedToken { TokenJti = "j1", UserId = "ghost", ExpiresAt = DateTime.UtcNow.AddMinutes(10) });
        SeedAttempts(db, "j1", count: 5);
        await db.SaveChangesAsync();

        deps.UserService.FindByIdAsync("ghost").Returns((User?)null);

        // act + assert
        var act = async () => await service.RunSweepAsync(CancellationToken.None);

        await act.Should().NotThrowAsync();
        await deps.TokenService.DidNotReceive().RevokeAllRefreshTokenFamiliesAsync(
            Arg.Any<string>(), Arg.Any<string>());
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task RunSweep_EmailSendFails_LockCascadeStillCompletes()
    {
        // arrange — security action must apply even if SMTP is down; email is informational, failure is logged not propagated.
        var (service, db, deps) = BuildService(warnThreshold: 2, lockThreshold: 5);
        var user = new User { Id = "u1", Email = "alice@example.com" };
        db.RevokedTokens.Add(new RevokedToken { TokenJti = "j1", UserId = "u1", ExpiresAt = DateTime.UtcNow.AddMinutes(10) });
        SeedAttempts(db, "j1", count: 5);
        await db.SaveChangesAsync();

        deps.UserService.FindByIdAsync("u1").Returns(user);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("tok");
        deps.EmailService
            .When(s => s.SendEmailAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>()))
            .Do(_ => throw new InvalidOperationException("smtp down"));

        // act + assert
        var act = async () => await service.RunSweepAsync(CancellationToken.None);

        await act.Should().NotThrowAsync();
        await deps.UserService.Received(1).SetLockoutEndDateAsync(user, LockoutDurations.Indefinite);
        await deps.TokenService.Received(1).RevokeAllRefreshTokenFamiliesAsync("u1", RevocationReasons.ReuseDetected);
    }

    [Fact]
    public async Task RunSweep_AuditRowsForUnknownJti_SkippedGracefully()
    {
        // arrange — audit rows for a jti with no matching RevokedToken row; shouldn't happen but must not crash.
        var (service, db, deps) = BuildService(warnThreshold: 2, lockThreshold: 5);
        SeedAttempts(db, "orphan-jti", count: 5);
        await db.SaveChangesAsync();

        // act + assert
        var act = async () => await service.RunSweepAsync(CancellationToken.None);

        await act.Should().NotThrowAsync();
        await deps.UserService.DidNotReceive().SetLockoutEndDateAsync(Arg.Any<User>(), Arg.Any<DateTimeOffset?>());
    }

    private static void SeedAttempts(DatabaseContext db, string jti, int count)
    {
        for (var i = 0; i < count; i++)
        {
            db.RevokedTokenAccessAttempts.Add(new RevokedTokenAccessAttempt
            {
                TokenJti = jti,
                UserId = "u1",
                IpAddress = "10.0.0.1",
                CreatedAt = DateTime.UtcNow.AddSeconds(-i),
            });
        }
    }

    private (RevokedTokenReplayEscalationService service, DatabaseContext db, EscalationDeps deps) BuildService(
        int warnThreshold = 2,
        int lockThreshold = 5)
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        var dbOptions = new DbContextOptionsBuilder<DatabaseContext>().UseSqlite(connection).Options;
        var db = new DatabaseContext(dbOptions);
        db.Database.EnsureCreated();
        _contexts.Add(db);

        var deps = new EscalationDeps
        {
            UserService = Substitute.For<IUserService>(),
            TokenService = Substitute.For<ITokenService>(),
            EmailService = Substitute.For<IEmailService>(),
        };

        var services = new ServiceCollection();
        services.AddDbContext<DatabaseContext>(opt => opt.UseSqlite(connection));
        services.AddSingleton(deps.UserService);
        services.AddSingleton(deps.TokenService);
        services.AddSingleton(deps.EmailService);
        var sp = services.BuildServiceProvider();
        _providers.Add(sp);

        var settings = Options.Create(new ThresholdEscalationSettings
        {
            Enabled = true,
            SweepIntervalInMinutes = 1,
            WindowInMinutes = 5,
            WarnThreshold = warnThreshold,
            LockThreshold = lockThreshold,
        });
        var publicUrl = Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" });

        var service = new RevokedTokenReplayEscalationService(
            NullLogger<RevokedTokenReplayEscalationService>.Instance,
            sp.GetRequiredService<IServiceScopeFactory>(),
            settings,
            publicUrl,
            TestMetricsFactory.Create());

        return (service, db, deps);
    }

    [Fact]
    public async Task RunSweep_WhenBodyThrows_SwallowsAndDoesNotPropagate()
    {
        // arrange
        var scopeFactory = Substitute.For<IServiceScopeFactory>();
        scopeFactory.CreateScope().Returns<IServiceScope>(_ => throw new InvalidOperationException("kaboom"));

        var settings = Options.Create(new ThresholdEscalationSettings
        {
            Enabled = true,
            SweepIntervalInMinutes = 1,
            WindowInMinutes = 5,
            WarnThreshold = 2,
            LockThreshold = 5,
        });
        var publicUrl = Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" });

        var service = new RevokedTokenReplayEscalationService(
            NullLogger<RevokedTokenReplayEscalationService>.Instance,
            scopeFactory,
            settings,
            publicUrl,
            TestMetricsFactory.Create());

        // act + assert
        var act = async () => await service.RunSweepAsync(CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    private sealed class EscalationDeps
    {
        public IUserService UserService { get; set; } = default!;
        public ITokenService TokenService { get; set; } = default!;
        public IEmailService EmailService { get; set; } = default!;
    }
}
