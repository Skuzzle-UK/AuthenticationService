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
/// <para><b>Scenario 11 — Admin invitation + lock/unlock lifecycle.</b></para>
///
/// <para>End-to-end exercise of the Phase 0 admin surface against real MySQL:</para>
/// <list type="number">
///   <item><description>Admin logs in with the seeded credentials.</description></item>
///   <item><description>Admin POSTs <c>/api/Admin/users</c> for a new user — DB row created with <c>EmailConfirmed=false</c> and no password hash.</description></item>
///   <item><description>Invitation email lands in smtp4dev; test extracts email + token from the link.</description></item>
///   <item><description>New user POSTs <c>/api/registration/accept-invitation</c> with a password — DB row flipped: <c>EmailConfirmed=true</c>, password hash set.</description></item>
///   <item><description>New user logs in with the new password — 200 + token pair.</description></item>
///   <item><description>Admin locks the new user — subsequent login attempt returns 401 with "account locked".</description></item>
///   <item><description>Admin unlocks — login works again.</description></item>
/// </list>
///
/// <para>This is the load-bearing assertion for the entire Phase 0 admin endpoint
/// surface — a regression here means an admin can't reliably create / manage users,
/// which breaks every downstream platform workflow that depends on the auth service
/// for identity management.</para>
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
        // ── act 1: log in as the seeded admin ────────────────────────────────────────
        var adminToken = await AuthenticateAsync(AdminEmail, AdminPassword);
        adminToken.Should().NotBeNullOrEmpty(
            because: "the seeded admin account must be usable for admin operations against the live host.");

        // ── act 2: admin invites a new user ──────────────────────────────────────────
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

        // ── assert DB: user exists with EmailConfirmed=false + no password ───────────
        await using (var db = await CreateDbContextAsync())
        {
            var dbUser = await db.Users.SingleAsync(u => u.Email == newEmail);
            dbUser.EmailConfirmed.Should().BeFalse(
                because: "invitation flow doesn't pre-confirm — that happens when the user clicks the link.");
            dbUser.PasswordHash.Should().BeNullOrEmpty(
                because: "the admin doesn't set a password; the user sets it via the invitation link.");
        }

        // ── act 3: parse the invitation email ────────────────────────────────────────
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

        // ── act 4: user accepts the invitation ───────────────────────────────────────
        // Drop the admin token — the accept-invitation endpoint is anonymous, and we
        // don't want the admin's bearer header sticking around for the user-side calls.
        AuthClient.DefaultRequestHeaders.Authorization = null;

        var userPassword = "InvitePassw0rd!";

        // Token in the email link is already Base64URL-encoded — pass it through as-is;
        // the accept-invitation endpoint decodes before handing to Identity.
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

        // ── act 5: user can now log in ───────────────────────────────────────────────
        var userToken = await AuthenticateAsync(newEmail, userPassword);
        userToken.Should().NotBeNullOrEmpty(
            because: "after invitation acceptance the user must be able to authenticate with their chosen password.");

        // ── act 6: admin locks the user ──────────────────────────────────────────────
        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        string newUserId;
        await using (var db = await CreateDbContextAsync())
        {
            newUserId = (await db.Users.SingleAsync(u => u.Email == newEmail)).Id;
        }

        var lockResp = await AuthClient.PostAsync($"/api/Admin/users/{newUserId}/lock", content: null);
        lockResp.IsSuccessStatusCode.Should().BeTrue();

        // ── assert: locked user can't log in ─────────────────────────────────────────
        AuthClient.DefaultRequestHeaders.Authorization = null;
        var lockedLoginResp = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/authenticate",
            new AuthenticationDto { Email = newEmail, Password = userPassword });

        lockedLoginResp.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            because: "after an admin lock the user's authentication attempts must be rejected.");

        // ── act 7: admin unlocks ─────────────────────────────────────────────────────
        AuthClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        var unlockResp = await AuthClient.PostAsync($"/api/Admin/users/{newUserId}/unlock", content: null);
        unlockResp.IsSuccessStatusCode.Should().BeTrue();

        // ── assert: user can log in again ────────────────────────────────────────────
        AuthClient.DefaultRequestHeaders.Authorization = null;
        var postUnlockToken = await AuthenticateAsync(newEmail, userPassword);
        postUnlockToken.Should().NotBeNullOrEmpty(
            because: "after admin-unlock the user must regain the ability to authenticate.");
    }

    /// <summary>
    /// Wrapper around the auth endpoint that returns just the access-token string. The
    /// base class's <see cref="IntegrationTestBase.LoginAsync"/> takes a
    /// <c>ConfirmedUser</c> built from the registration flow — this scenario creates
    /// users through the admin flow instead so we can't reuse it.
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
