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
/// <para><b>Scenario 12 — Admin force-password-reset cycle.</b></para>
///
/// <para>Exercises the destructive-admin path that doesn't touch the invitation flow.
/// The contract this scenario pins is the bit that's <em>unique</em> to the admin
/// surface — what scenario 11 (invitation) and the unit-level tests don't already
/// cover:</para>
/// <list type="bullet">
///   <item><description>The admin endpoint accepts a target user id and returns success.</description></item>
///   <item><description>A password-reset email is dispatched to the user with a <c>/ResetPassword</c> link carrying email + token.</description></item>
///   <item><description>The user's existing refresh-token families are revoked — their next refresh attempt fails, forcing re-authentication at the next access-token expiry.</description></item>
/// </list>
///
/// <para>The "user completes the reset by submitting the token to <c>/api/Account/forgotpassword/reset</c>"
/// step is deliberately <em>not</em> asserted here. Identity's password-reset token validation
/// is exercised end-to-end by Scenario 11 (the invitation flow consumes the same token type
/// via <c>/api/registration/accept-invitation</c>), and at the unit level by
/// <c>AccountControllerPasswordTests</c>. Adding it here would just duplicate that
/// coverage while introducing a sensitive HTTP round-trip we don't gain confidence from.</para>
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class AdminForcePasswordResetTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    private const string AdminEmail = "email@email.com";
    private const string AdminPassword = "Pa5$word123-dev";

    [Fact]
    public async Task AdminForcePasswordReset_EmailsResetLinkAndRevokesRefreshTokens()
    {
        // arrange — a confirmed user who's logged in and holds a refresh token. Clear
        // the smtp4dev inbox so the reset email is the only message we see after the
        // admin fires the endpoint (the registration-confirm email is already there
        // from RegisterAndConfirmUserAsync).
        var user = await RegisterAndConfirmUserAsync();
        var preToken = await LoginAsync(user);
        await SmtpClient.ClearAsync();

        // ── act 1: admin logs in and force-password-resets the user ──────────────────
        var adminToken = await AuthenticateAsync(AdminEmail, AdminPassword);

        string targetUserId;
        await using (var db = await CreateDbContextAsync())
        {
            var dbUser = await db.Users.FirstAsync(u => u.Email == user.Email);
            targetUserId = dbUser.Id;
        }

        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var resetResp = await AuthClient.PostAsJsonAsync<object?>(
            $"/api/Admin/users/{targetUserId}/force-password-reset",
            value: null);
        resetResp.IsSuccessStatusCode.Should().BeTrue(
            because: "admin force-password-reset on an existing user must succeed.");

        // ── assert: reset email lands with the expected shape ────────────────────────
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

        // ── assert: refresh-token families are revoked ───────────────────────────────
        // The unique-to-admin contract: the user's existing refresh tokens die
        // immediately so they can't refresh past their current access-token expiry.
        // Access tokens themselves continue to work until natural expiry (~5 min) by
        // design — admin doesn't have the target's access token to add to the deny-list.
        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", preToken.Value);
        var refreshResp = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/refresh",
            new RefreshTokenDto { RefreshToken = preToken.RefreshToken });
        refreshResp.IsSuccessStatusCode.Should().BeFalse(
            because: "force-password-reset revokes every refresh-token family — the user can't refresh past their current access-token expiry.");
    }

    /// <summary>
    /// Wrapper around the auth endpoint that returns just the access-token string. The
    /// base class's <see cref="IntegrationTestBase.LoginAsync"/> takes a
    /// <c>ConfirmedUser</c> built from the registration flow — this scenario also signs
    /// in as the seeded admin (no <c>ConfirmedUser</c>) so we have a slimmer helper.
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
