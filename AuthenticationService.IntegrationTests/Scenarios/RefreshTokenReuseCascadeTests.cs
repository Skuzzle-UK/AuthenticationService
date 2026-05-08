using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationService.Constants;
using AuthenticationService.Shared.Dtos;
using AwesomeAssertions;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// <para><b>Scenario 3 — Refresh-token reuse cascade.</b></para>
///
/// <para>The single most security-critical flow in the auth service: when a refresh
/// token is presented twice (because it leaked, was stolen, or the legitimate user is
/// being phished), the service treats the second attempt as proof of compromise and
/// nukes everything. Specifically:</para>
/// <list type="bullet">
///   <item><description>Every refresh-token row for the user is revoked (forces re-login on every device).</description></item>
///   <item><description>The user's security stamp is rotated, invalidating every outstanding access token at the JwtBearer middleware layer.</description></item>
///   <item><description>A suspicious-activity email is sent so the legitimate user (if it was them being phished) knows to change their password.</description></item>
///   <item><description>The HTTP response is a generic 401 — deliberately indistinguishable from an Expired or NotFound result so an attacker can't tell they've been caught.</description></item>
/// </list>
///
/// <para>Unit tests cover each of these in isolation. This integration test asserts the
/// full chain fires end-to-end against real MySQL (for the row state + stamp), real
/// Redis (for the data-protection key ring that protects the stamp claim), and real
/// SMTP (for the user notification). If any link breaks, this test fails — and a
/// silent regression here would mean compromised refresh tokens stay usable.</para>
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class RefreshTokenReuseCascadeTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task SecondRefreshWithConsumedToken_TriggersFullCascadeAndNotifiesUser()
    {
        // arrange — confirmed user, logged in. Capture the initial security stamp + the
        // user's database ID so later assertions can compare.
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

        // act 1 — first refresh succeeds. R1 is now consumed in the database. (Scenario 2
        // already asserts this in detail; here it's a setup step, not the thing under test.)
        var firstRefresh = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/refresh",
            new RefreshTokenDto { RefreshToken = firstToken.RefreshToken });
        firstRefresh.IsSuccessStatusCode.Should().BeTrue(
            because: "the first refresh of an unconsumed token must succeed — this is setup, not the assertion.");

        // Clear smtp4dev so the suspicious-activity assertion below isn't confused by
        // the registration-confirmation email left over in the mailbox.
        await SmtpClient.ClearAsync();

        // act 2 — second refresh with the *same* (now-consumed) refresh token. The
        // service detects reuse, fires the full cascade synchronously (all families
        // revoked + security stamp rotated) inside RotateRefreshTokenAsync, then the
        // controller calls HandleReuseDetectedAsync which sends the email + logs
        // Critical SIEM event + returns 401.
        var secondRefresh = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/refresh",
            new RefreshTokenDto { RefreshToken = firstToken.RefreshToken });

        // assert — generic 401, deliberately indistinguishable from any other refresh
        // failure so an attacker probing with a stolen token can't tell they've been
        // caught from the response shape alone.
        secondRefresh.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "reuse detection responds with a generic 401 — the same shape NotFound / Expired produce.");

        // assert — suspicious-activity email arrived in smtp4dev. This is the
        // out-of-band signal to the legitimate user (if it was them being phished) that
        // their account needs attention.
        var message = await SmtpClient.WaitForMessageAsync(user.Email, TimeSpan.FromSeconds(10));
        message.Should().NotBeNull(
            because: "reuse detection must notify the user so they can change their password.");
        message!.Subject.Should().Be(EmailSubjects.SuspiciousActivity);

        // assert — DB-side state matches: every refresh token for the user is now
        // consumed (no live refresh tokens remain), and the security stamp has rotated
        // (which invalidates every outstanding access token via JwtBearer's stamp-claim
        // check on subsequent authenticated requests).
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
