using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationService.Constants;
using AuthenticationService.Shared.Dtos;
using AwesomeAssertions;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// Scenario 3 — Refresh-token reuse cascade. The single most security-critical flow:
/// presenting a refresh token twice triggers full revocation (all families consumed +
/// security stamp rotated + suspicious-activity email + generic 401 response). Asserts
/// the full chain end-to-end against real MySQL + Redis + SMTP — a silent regression
/// here would leave compromised refresh tokens usable.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class RefreshTokenReuseCascadeTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task SecondRefreshWithConsumedToken_TriggersFullCascadeAndNotifiesUser()
    {
        // arrange
        var user = await RegisterAndConfirmUserAsync();
        var firstToken = await LoginAsync(user);

        string initialSecurityStamp;
        string userId;
        await using (var db = await CreateDbContextAsync())
        {
            var dbUser = await db.Users.SingleAsync(u => u.Email == user.Email);
            initialSecurityStamp = dbUser.SecurityStamp!;
            userId = dbUser.Id;
        }

        AuthClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", firstToken.Value);

        // act — phase 1: first refresh consumes R1 (setup, covered by Scenario 2)
        var firstRefresh = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/refresh",
            new RefreshTokenDto { RefreshToken = firstToken.RefreshToken });

        // assert — phase 1
        firstRefresh.IsSuccessStatusCode.Should().BeTrue(
            because: "the first refresh of an unconsumed token must succeed — this is setup, not the assertion.");

        // Clear inbox so the suspicious-activity assertion isn't confused by the
        // registration-confirmation email.
        await SmtpClient.ClearAsync();

        // act — phase 2: second refresh with the now-consumed token triggers the cascade
        var secondRefresh = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/refresh",
            new RefreshTokenDto { RefreshToken = firstToken.RefreshToken });

        // assert — phase 2
        secondRefresh.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "reuse detection responds with a generic 401 — the same shape NotFound / Expired produce.");

        var message = await SmtpClient.WaitForMessageAsync(user.Email, TimeSpan.FromSeconds(10));
        message.Should().NotBeNull(
            because: "reuse detection must notify the user so they can change their password.");
        message!.Subject.Should().Be(EmailSubjects.SuspiciousActivity);

        await using (var db = await CreateDbContextAsync())
        {
            var rows = await db.RefreshTokens
                .AsNoTracking()
                .Where(r => r.UserId == userId)
                .ToListAsync();
            rows.Should().NotBeEmpty(
                because: "the user has had at least two refresh tokens issued (original + first rotation).");
            rows.Should().AllSatisfy(r => r.ConsumedAt.Should().NotBeNull(
                because: "the reuse cascade revokes every active refresh-token row for the user."));

            var dbUser = await db.Users.AsNoTracking().SingleAsync(u => u.Id == userId);
            dbUser.SecurityStamp.Should().NotBe(initialSecurityStamp,
                because: "stamp rotation is what invalidates outstanding access tokens; without it, T1 + T2 would keep working until natural expiry.");
        }
    }
}
