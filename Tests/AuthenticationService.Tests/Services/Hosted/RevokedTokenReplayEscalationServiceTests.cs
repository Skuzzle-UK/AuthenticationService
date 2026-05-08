using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Services.Hosted;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
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
/// <para><see cref="RevokedTokenReplayEscalationService"/>'s timer wraps a single
/// deterministic pass: <c>RunSweepAsync</c>. Tests drive the sweep directly via the
/// <c>internal</c>-exposed method.</para>
///
/// <para>Branches covered:</para>
/// <list type="bullet">
///   <item><description>No replays in window → no-op; no DB writes, no log events.</description></item>
///   <item><description>Replays at warn threshold → fires warn event, stamps <c>WarnedAt</c>; no lock cascade.</description></item>
///   <item><description>Subsequent sweep with the same warned state → no re-fire (idempotency via <c>WarnedAt</c>).</description></item>
///   <item><description>Replays at lock threshold → cascade fires (lock + revoke families + stamp rotation + email).</description></item>
///   <item><description>Subsequent sweep after lock → no re-cascade (idempotency via <c>LockedAt</c>).</description></item>
///   <item><description>Lock cascade for missing user (deleted out-of-band) → log warning, skip cascade gracefully.</description></item>
///   <item><description>Lock cascade with email-send failure → security action still applied; failure logged not propagated.</description></item>
///   <item><description>Audit row for unknown jti (no matching <see cref="RevokedToken"/>) → skipped gracefully.</description></item>
/// </list>
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
    }

    [Fact]
    public async Task RunSweep_NoReplaysInWindow_NoOp()
    {
        // arrange — empty audit table.
        var (service, db, deps) = BuildService();

        // act
        await service.RunSweepAsync(CancellationToken.None);

        // assert — no email sent, no token-service interaction.
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
        await deps.TokenService.DidNotReceive().RevokeAllRefreshTokenFamiliesAsync(
            Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task RunSweep_AttemptsAtWarnThreshold_StampsWarnedAtButDoesNotLock()
    {
        // arrange — 2 replays (matching default WarnThreshold = 2). Should warn but
        // not lock.
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
        // arrange — same row but WarnedAt already populated. Idempotent skip.
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

        // assert — WarnedAt unchanged.
        db.ChangeTracker.Clear();
        (await db.RevokedTokens.SingleAsync()).WarnedAt
            .Should().BeCloseTo(originalWarnedAt, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task RunSweep_AttemptsAtLockThreshold_CascadesLockRevokeAndEmail()
    {
        // arrange — 5 replays (lock threshold). Cascade: indefinite lock, revoke all
        // families, rotate stamp, send recovery email, log Critical SIEM event.
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
        // arrange — LockedAt already populated. Even with continued replay, idempotency
        // prevents re-firing (the user is already locked — no point sending another email).
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

        // assert — none of the cascade ran.
        await deps.UserService.DidNotReceive().SetLockoutEndDateAsync(Arg.Any<User>(), Arg.Any<DateTimeOffset?>());
        await deps.TokenService.DidNotReceive().RevokeAllRefreshTokenFamiliesAsync(Arg.Any<string>(), Arg.Any<string>());
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task RunSweep_LockUserMissing_LogsAndSkipsCascade()
    {
        // arrange — user behind the revoked token has been deleted. Service must log
        // and continue rather than crash.
        var (service, db, deps) = BuildService(warnThreshold: 2, lockThreshold: 5);
        db.RevokedTokens.Add(new RevokedToken { TokenJti = "j1", UserId = "ghost", ExpiresAt = DateTime.UtcNow.AddMinutes(10) });
        SeedAttempts(db, "j1", count: 5);
        await db.SaveChangesAsync();

        deps.UserService.FindByIdAsync("ghost").Returns((User?)null);

        // act
        var act = async () => await service.RunSweepAsync(CancellationToken.None);

        // assert — no throw, no token-service call (since there's no user to lock).
        await act.Should().NotThrowAsync();
        await deps.TokenService.DidNotReceive().RevokeAllRefreshTokenFamiliesAsync(
            Arg.Any<string>(), Arg.Any<string>());
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task RunSweep_EmailSendFails_LockCascadeStillCompletes()
    {
        // arrange — security action (lock + revoke + stamp rotation) must take effect
        // even if SMTP is down. The email is informational; failure to send is logged
        // not propagated.
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

        // act
        var act = async () => await service.RunSweepAsync(CancellationToken.None);

        // assert
        await act.Should().NotThrowAsync();
        await deps.UserService.Received(1).SetLockoutEndDateAsync(user, LockoutDurations.Indefinite);
        await deps.TokenService.Received(1).RevokeAllRefreshTokenFamiliesAsync("u1", RevocationReasons.ReuseDetected);
    }

    [Fact]
    public async Task RunSweep_AuditRowsForUnknownJti_SkippedGracefully()
    {
        // arrange — audit rows for a jti with no matching RevokedToken row (data-shape
        // mismatch shouldn't happen under normal flows but the service must not crash).
        var (service, db, deps) = BuildService(warnThreshold: 2, lockThreshold: 5);
        SeedAttempts(db, "orphan-jti", count: 5);
        await db.SaveChangesAsync();

        // act
        var act = async () => await service.RunSweepAsync(CancellationToken.None);

        // assert
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

        // Real ServiceProvider so the service's CreateScope() resolves through it.
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
            publicUrl);

        return (service, db, deps);
    }

    private sealed class EscalationDeps
    {
        public IUserService UserService { get; set; } = default!;
        public ITokenService TokenService { get; set; } = default!;
        public IEmailService EmailService { get; set; } = default!;
    }
}
