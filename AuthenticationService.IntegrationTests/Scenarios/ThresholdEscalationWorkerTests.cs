using System.Diagnostics.Metrics;
using Aspire.Hosting.Testing;
using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Observability;
using AuthenticationService.Services;
using AuthenticationService.Services.Hosted;
using AuthenticationService.Settings;
using AuthenticationService.Storage;
using AwesomeAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// <para><b>Scenario 6 — Threshold escalation worker.</b></para>
///
/// <para>The worker that watches the <c>RevokedTokenAccessAttempts</c> audit table for
/// sustained replay of revoked access tokens, and (once the lock threshold is crossed)
/// locks the account indefinitely. The unit tests cover this against SQLite — this
/// scenario exercises the same <c>RunSweepAsync</c> method against the real running
/// MySQL instance to catch any provider-specific query divergences (the sweep uses
/// <c>GroupBy</c>, <c>ToDictionaryAsync</c>, and tracked-entity mutations — all surfaces
/// where MySql.EntityFrameworkCore could diverge from SQLite-InMemory).</para>
///
/// <para>We invoke the worker directly via its <c>internal RunSweepAsync</c> method
/// (made visible to this assembly via <c>InternalsVisibleTo</c>) rather than waiting
/// for its 1-minute PeriodicTimer to fire — same pattern the unit tests use, just
/// pointed at real MySQL via Aspire's connection string. The cascade actions
/// (lockout / family revocation / email send) are substituted because they're
/// individually integration-tested elsewhere (Scenarios 3, 4); this test's value is
/// confirming the worker's SQL-against-MySQL piece works end-to-end.</para>
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class ThresholdEscalationWorkerTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task RunSweep_OnRealMySql_StampsLockedAtAndFiresCascade()
    {
        // arrange — confirmed user. We need a real DB row for the User so the worker
        // can lock them; RegisterAndConfirmUserAsync gives us one.
        var user = await RegisterAndConfirmUserAsync();

        // Insert worker-input state directly into the real MySQL: one revoked-token row
        // and 5 access-attempt rows pointing at it (5 = the configured lock threshold).
        // The worker will detect this on its sweep and trigger the lock cascade.
        var revokedJti = Guid.NewGuid().ToString();
        string userId;
        await using (var setupDb = await CreateDbContextAsync())
        {
            var dbUser = await setupDb.Users.SingleAsync(u => u.Email == user.Email);
            userId = dbUser.Id;

            setupDb.RevokedTokens.Add(new RevokedToken
            {
                TokenJti = revokedJti,
                UserId = dbUser.Id,
                ExpiresAt = DateTime.UtcNow.AddMinutes(10),
                RevokedAt = DateTime.UtcNow,
                RevocationReason = RevocationReasons.Logout,
            });

            for (var i = 0; i < 5; i++)
            {
                setupDb.RevokedTokenAccessAttempts.Add(new RevokedTokenAccessAttempt
                {
                    TokenJti = revokedJti,
                    UserId = dbUser.Id,
                    IpAddress = "10.0.0.99",
                    CreatedAt = DateTime.UtcNow.AddSeconds(-i),
                });
            }
            await setupDb.SaveChangesAsync();
        }

        // Build a service provider that:
        //  - Resolves DatabaseContext to the real MySQL via Aspire's connection string
        //    (so the worker's Where + GroupBy + ToDictionaryAsync execute against real
        //    MySQL — not SQLite-InMemory, which the unit tests use)
        //  - Substitutes IUserService / ITokenService / IEmailService so the cascade
        //    actions are introspectable. Each is independently exercised by other
        //    integration tests (Scenarios 3, 4) and unit tests, so re-asserting their
        //    full behaviour here would be duplicative.
        var connectionString = await Fixture.App.GetConnectionStringAsync("AuthenticationService")
            ?? throw new InvalidOperationException("MySQL connection string not exposed by Aspire.");

        var userService = Substitute.For<IUserService>();
        var tokenService = Substitute.For<ITokenService>();
        var emailService = Substitute.For<IEmailService>();

        // The worker calls FindByIdAsync to get the User it will lock; return a fresh
        // User instance with the real ID + email so the rest of ApplyLockAsync proceeds.
        userService.FindByIdAsync(userId).Returns(new User
        {
            Id = userId,
            Email = user.Email,
            UserName = user.UserName,
        });
        userService.GeneratePasswordResetTokenAsync(Arg.Any<User>()).Returns("reset-tok");

        var services = new ServiceCollection();
        services.AddDbContext<DatabaseContext>(opt => opt.UseMySQL(connectionString));
        services.AddSingleton(userService);
        services.AddSingleton(tokenService);
        services.AddSingleton(emailService);
        await using var sp = services.BuildServiceProvider();

        var settings = Options.Create(new ThresholdEscalationSettings
        {
            Enabled = true,
            SweepIntervalInMinutes = 1,
            WindowInMinutes = 5,
            WarnThreshold = 2,
            LockThreshold = 5,
        });
        var publicUrl = Options.Create(new PublicUrlSettings { BaseUrl = "https://test.local" });

        var worker = new RevokedTokenReplayEscalationService(
            NullLogger<RevokedTokenReplayEscalationService>.Instance,
            sp.GetRequiredService<IServiceScopeFactory>(),
            settings,
            publicUrl,
            CreateAuthMetrics());

        // act — run one sweep against real MySQL.
        await worker.RunSweepAsync(CancellationToken.None);

        // assert (DB-side) — the revoked-token row in real MySQL has been stamped with
        // both WarnedAt (5 attempts ≥ warn threshold of 2) and LockedAt (5 ≥ lock
        // threshold of 5). This is the load-bearing assertion: it confirms the
        // GroupBy + ToDictionary + tracked-entity SaveChanges pattern survives the
        // MySql.EntityFrameworkCore translation.
        await using (var assertDb = await CreateDbContextAsync())
        {
            var stamped = await assertDb.RevokedTokens
                .AsNoTracking()
                .SingleAsync(r => r.TokenJti == revokedJti);

            stamped.WarnedAt.Should().NotBeNull(
                because: "5 replay attempts ≥ warn threshold of 2 — the worker must stamp WarnedAt.");
            stamped.LockedAt.Should().NotBeNull(
                because: "5 replay attempts ≥ lock threshold of 5 — the worker must stamp LockedAt.");
        }

        // assert (cascade-side) — the worker invoked the three cascade dependencies in
        // the right shape. Detailed behaviour of each is covered by the dedicated unit
        // tests for IUserService / ITokenService / QueuedEmailService.
        await userService.Received(1).SetLockoutEndDateAsync(
            Arg.Is<User>(u => u.Id == userId),
            LockoutDurations.Indefinite);
        await tokenService.Received(1).RevokeAllRefreshTokenFamiliesAsync(
            userId,
            RevocationReasons.ReuseDetected);
        await userService.Received(1).UpdateSecurityStampAsync(
            Arg.Is<User>(u => u.Id == userId));
        await emailService.Received(1).SendEmailAsync(
            user.Email,
            EmailSubjects.SuspiciousActivity,
            Arg.Any<string>());
    }

    // AuthMetrics needs an IMeterFactory; the scenario fixture's DI graph doesn't
    // surface one here. A real factory off the default DI extension is fine — the
    // meter has no listener so the increments are no-ops, but the metric methods
    // run their full code path which is what we want.
    private static AuthMetrics CreateAuthMetrics()
    {
        var sp = new ServiceCollection().AddMetrics().BuildServiceProvider();
        return new AuthMetrics(sp.GetRequiredService<IMeterFactory>());
    }
}
