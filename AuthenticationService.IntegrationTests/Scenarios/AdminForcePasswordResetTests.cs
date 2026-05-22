using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationService.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AwesomeAssertions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// Scenario 12 — Admin force-password-reset cycle. Asserts the admin-unique bits:
/// endpoint succeeds, a reset-link email is dispatched, and the user's refresh-token
/// families are revoked. The user-submits-token step is deliberately not re-asserted
/// here — Scenario 11 + AccountControllerPasswordTests already cover Identity's
/// reset-token validation.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class AdminForcePasswordResetTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    private const string AdminEmail = "email@email.com";
    private const string AdminPassword = "Pa5$word123-dev";

    [Fact]
    public async Task AdminForcePasswordReset_EmailsResetLinkAndRevokesRefreshTokens()
    {
        // arrange
        var user = await RegisterAndConfirmUserAsync();
        var preToken = await LoginAsync(user);
        // Clear inbox so the reset email is the only message after the admin fires —
        // the registration-confirm email is already there.
        await SmtpClient.ClearAsync();

        var adminToken = await AuthenticateAsync(AdminEmail, AdminPassword);

        string targetUserId;
        await using (var db = await CreateDbContextAsync())
        {
            var dbUser = await db.Users.FirstAsync(u => u.Email == user.Email);
            targetUserId = dbUser.Id;
        }

        // act — phase 1: admin force-password-reset
        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var resetResp = await AuthClient.PostAsJsonAsync<object?>(
            $"/api/Admin/users/{targetUserId}/force-password-reset",
            value: null);

        // assert — phase 1
        resetResp.IsSuccessStatusCode.Should().BeTrue(
            because: "admin force-password-reset on an existing user must succeed.");

        var msg = await SmtpClient.WaitForMessageAsync(user.Email, TimeSpan.FromSeconds(10));
        msg.Should().NotBeNull(
            because: "force-password-reset must enqueue an outgoing email to the target user.");
        msg!.Subject.Should().Be(EmailSubjects.PasswordReset);

        var body = await SmtpClient.GetMessageHtmlAsync(msg.Id);
        var resetLink = MailLinkExtractor.FindLinkContaining(body, "/ResetPassword");
        resetLink.Should().NotBeNull(
            because: "the reset email must embed a link to the ResetPassword page.");

        var linkQuery = QueryHelpers.ParseQuery(resetLink!.Query);
        linkQuery["email"].ToString().Should().Be(user.Email,
            because: "the reset link must carry the target user's email as a query param.");
        linkQuery["token"].ToString().Should().NotBeNullOrEmpty(
            because: "the reset link must carry the password-reset token as a query param.");

        // act — phase 2: pre-reset refresh token attempt
        // Admin-unique contract: refresh-token families die immediately so the user
        // can't refresh past their current access-token expiry. Access tokens themselves
        // continue working until natural expiry (~5 min) — admin doesn't have the
        // target's access token to add to the deny-list.
        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", preToken.Value);
        var refreshResp = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/refresh",
            new RefreshTokenDto { RefreshToken = preToken.RefreshToken });

        // assert — phase 2
        refreshResp.IsSuccessStatusCode.Should().BeFalse(
            because: "force-password-reset revokes every refresh-token family — the user can't refresh past their current access-token expiry.");
    }

    /// <summary>
    /// Returns just the access-token string. Used for the seeded admin where the base
    /// class's LoginAsync (which takes a ConfirmedUser) doesn't fit.
    /// </summary>
    private async Task<string> AuthenticateAsync(string email, string password)
    {
        var resp = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/authenticate",
            new AuthenticationDto { Email = email, Password = password });
        resp.IsSuccessStatusCode.Should().BeTrue(
            because: $"authenticating as {email} must succeed at this point in the scenario.");

        var body = await resp.Content.ReadFromJsonAsync<AuthenticationResponse>()
            ?? throw new InvalidOperationException("Authentication response body deserialised to null.");
        return body.Token?.Value ?? throw new InvalidOperationException("Authentication response carried no token.");
    }
}
