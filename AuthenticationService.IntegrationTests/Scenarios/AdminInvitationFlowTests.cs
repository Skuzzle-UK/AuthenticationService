using System.Net;
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
/// Scenario 11 — Admin invitation + lock/unlock lifecycle against real MySQL. End-to-end
/// for the Phase 0 admin surface: admin creates user → invitation email → user accepts +
/// sets password → user logs in → admin locks + unlocks. Load-bearing for every
/// downstream platform workflow that depends on auth for identity management.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class AdminInvitationFlowTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    // Matches appsettings.json + appsettings.Development.json — the seeded admin.
    private const string AdminEmail = "email@email.com";
    private const string AdminPassword = "Pa5$word123-dev";

    [Fact]
    public async Task AdminInvitesUser_UserAccepts_Logs_In_LocksAndUnlocks()
    {
        var adminToken = await AuthenticateAsync(AdminEmail, AdminPassword);
        adminToken.Should().NotBeNullOrEmpty(
            because: "the seeded admin account must be usable for admin operations against the live host.");

        var newEmail = UniqueEmail();
        var newUserName = UniqueUserName();
        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);

        var createResp = await AuthClient.PostAsJsonAsync(
            "/api/Admin/users",
            new AdminCreateUserDto
            {
                Email = newEmail,
                UserName = newUserName,
                FirstName = "Pending",
                LastName = "User",
            });

        createResp.StatusCode.Should().Be(HttpStatusCode.Created,
            because: "admin-creates-user with a fresh email/username must succeed.");

        await using (var db = await CreateDbContextAsync())
        {
            var dbUser = await db.Users.SingleAsync(u => u.Email == newEmail);
            dbUser.EmailConfirmed.Should().BeFalse(
                because: "invitation flow doesn't pre-confirm — that happens when the user clicks the link.");
            dbUser.PasswordHash.Should().BeNullOrEmpty(
                because: "the admin doesn't set a password; the user sets it via the invitation link.");
        }

        var msg = await SmtpClient.WaitForMessageAsync(newEmail, TimeSpan.FromSeconds(10));
        msg.Should().NotBeNull(
            because: "invitation email must be queued + dispatched within the timeout.");
        msg!.Subject.Should().Be(EmailSubjects.AccountInvitation);

        var body = await SmtpClient.GetMessageHtmlAsync(msg.Id);
        var inviteLink = MailLinkExtractor.FindLinkContaining(body, "/AcceptInvitation");
        inviteLink.Should().NotBeNull(
            because: "the invitation email must contain a link to the AcceptInvitation page.");

        var query = QueryHelpers.ParseQuery(inviteLink!.Query);
        var emailFromLink = query["email"].ToString();
        var tokenFromLink = query["token"].ToString();
        emailFromLink.Should().Be(newEmail);
        tokenFromLink.Should().NotBeNullOrEmpty();

        // Accept-invitation is anonymous — drop the admin header to avoid ambiguity.
        AuthClient.DefaultRequestHeaders.Authorization = null;

        var userPassword = "InvitePassw0rd!";

        // Token is Base64URL-encoded in the link; pass through as-is — endpoint decodes.
        var acceptResp = await AuthClient.PostAsJsonAsync(
            "/api/Registration/accept-invitation",
            new AcceptInvitationDto
            {
                Email = newEmail,
                Token = tokenFromLink,
                NewPassword = userPassword,
            });

        acceptResp.IsSuccessStatusCode.Should().BeTrue(
            because: "the invitation token + a valid password is the supported activation path.");

        await using (var db = await CreateDbContextAsync())
        {
            var dbUser = await db.Users.SingleAsync(u => u.Email == newEmail);
            dbUser.EmailConfirmed.Should().BeTrue(
                because: "the accept-invitation endpoint flips EmailConfirmed in the same transaction as the password set.");
            dbUser.PasswordHash.Should().NotBeNullOrEmpty(
                because: "the password supplied to accept-invitation must be hashed into the user row.");
        }

        var userToken = await AuthenticateAsync(newEmail, userPassword);
        userToken.Should().NotBeNullOrEmpty(
            because: "after invitation acceptance the user must be able to authenticate with their chosen password.");

        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        string newUserId;
        await using (var db = await CreateDbContextAsync())
        {
            newUserId = (await db.Users.SingleAsync(u => u.Email == newEmail)).Id;
        }

        var lockResp = await AuthClient.PostAsync($"/api/Admin/users/{newUserId}/lock", content: null);
        lockResp.IsSuccessStatusCode.Should().BeTrue();

        AuthClient.DefaultRequestHeaders.Authorization = null;
        var lockedLoginResp = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/authenticate",
            new AuthenticationDto { Email = newEmail, Password = userPassword });

        lockedLoginResp.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "after an admin lock the user's authentication attempts must be rejected.");

        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var unlockResp = await AuthClient.PostAsync($"/api/Admin/users/{newUserId}/unlock", content: null);
        unlockResp.IsSuccessStatusCode.Should().BeTrue();

        AuthClient.DefaultRequestHeaders.Authorization = null;
        var postUnlockToken = await AuthenticateAsync(newEmail, userPassword);
        postUnlockToken.Should().NotBeNullOrEmpty(
            because: "after admin-unlock the user must regain the ability to authenticate.");
    }

    /// <summary>
    /// Returns just the access-token string. Base class's LoginAsync takes a
    /// ConfirmedUser from the registration flow — this scenario uses the admin flow instead.
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
