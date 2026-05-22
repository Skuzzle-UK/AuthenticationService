using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AwesomeAssertions;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// Scenario 2 — Refresh token rotation persists correctly through real MySQL. Asserts
/// both halves of the pair rotate, the old row is marked consumed with ReplacedByTokenId
/// pointing at the new row, and the new row stays in the same FamilyId. Catches a
/// regression of consume-on-rotate, which would silently let a refresh token be used
/// twice without triggering the reuse cascade.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class RefreshTokenRotationTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task Refresh_RotatesPair_AndMarksOldRefreshConsumedInDatabase()
    {
        // arrange
        var user = await RegisterAndConfirmUserAsync();
        var firstToken = await LoginAsync(user);

        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            scheme: "Bearer",
            parameter: firstToken.Value);

        // act
        var refreshResponse = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/refresh",
            new RefreshTokenDto { RefreshToken = firstToken.RefreshToken });

        // assert
        refreshResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "an unconsumed refresh token paired with a still-signature-valid access token rotates cleanly.");
        var refreshed = await refreshResponse.Content.ReadFromJsonAsync<AuthenticationResponse>();
        refreshed.Should().NotBeNull();
        refreshed!.Token.Should().NotBeNull();
        refreshed.Token!.Value.Should().NotBe(firstToken.Value,
            because: "the access token must be a fresh JWT, not the same one with a re-stamped expiry.");
        refreshed.Token.RefreshToken.Should().NotBe(firstToken.RefreshToken,
            because: "the refresh half must rotate too — otherwise reuse detection couldn't fire.");

        await using var db = await CreateDbContextAsync();
        var dbUser = await db.Users.SingleAsync(u => u.Email == user.Email);

        var rows = await db.RefreshTokens
            .Where(r => r.UserId == dbUser.Id)
            .OrderBy(r => r.CreatedAt)
            .ToListAsync();

        rows.Should().HaveCount(2,
            because: "rotation creates a new row and marks the original consumed; both rows persist for forensic / reuse-detection lookups.");

        var original = rows[0];
        var rotated = rows[1];

        original.ConsumedAt.Should().NotBeNull(
            because: "the rotated-from row must carry a consumed-at timestamp — that's what reuse detection checks against.");
        original.ReplacedByTokenId.Should().Be(rotated.Id,
            because: "the consume step records which row replaced this one so reuse detection can identify the live family member via an explicit FK rather than CreatedAt ordering.");
        rotated.ConsumedAt.Should().BeNull(
            because: "the new row is the live refresh token — not yet consumed.");
        rotated.FamilyId.Should().Be(original.FamilyId,
            because: "rotation stays inside one family; only a reuse cascade branches family IDs.");
    }
}
