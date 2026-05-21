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
/// Scenario 6 — Threshold escalation worker against real MySQL. Unit tests cover the
/// worker against SQLite; this catches provider-specific query divergences (sweep uses
/// GroupBy + ToDictionaryAsync + tracked mutations, all surfaces where
/// MySql.EntityFrameworkCore can diverge from SQLite-InMemory). Cascade actions are
/// substituted because Scenarios 3 + 4 integration-test them; this test's value is the
/// SQL piece end-to-end.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class ThresholdEscalationWorkerTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task RunSweep_OnRealMySql_StampsLockedAtAndFiresCascade()
    {
        var user = await RegisterAndConfirmUserAsync();

        // Seed: one revoked-token row + 5 access-attempt rows pointing at it (5 = the
        // configured lock threshold). Worker detects this and triggers the cascade.
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

        // DI: real MySQL DbContext + substituted cascade services (full cascade
        // behaviour is covered in Scenarios 3 + 4).
        var connectionString = await Fixture.App.GetConnectionStringAsync("AuthenticationService")
            ?? throw new InvalidOperationException("MySQL connection string not exposed by Aspire.");

        var userService = Substitute.For<IUserService>();
        var tokenService = Substitute.For<ITokenService>();
        var emailService = Substitute.For<IEmailService>();

        // Worker calls FindByIdAsync to get the User it will lock — return a real-ID instance.
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

        await worker.RunSweepAsync(CancellationToken.None);

        // Load-bearing assertion: the GroupBy + ToDictionary + tracked-entity SaveChanges
        // pattern survives the MySql.EntityFrameworkCore translation.
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

    // AuthMetrics needs an IMeterFactory. A real factory with no listener works —
    // increments are no-ops but the metric code paths run.
    private static AuthMetrics CreateAuthMetrics()
    {
        var sp = new ServiceCollection().AddMetrics().BuildServiceProvider();
        return new AuthMetrics(sp.GetRequiredService<IMeterFactory>());
    }
}
