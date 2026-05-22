using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationService.Constants;
using AuthenticationService.Shared.Dtos;
using AwesomeAssertions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// Scenario 4 — Password change → "wasn't me!" → account lock. The "panic button"
/// recovery path: the password-changed email contains a link the legitimate user clicks
/// if it wasn't them, locking the account indefinitely. Catches regressions in the link
/// builder / token-purpose chain that would silently break the user clicking "wasn't me"
/// and nothing happening.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class PasswordChangeLockAccountTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task PasswordChange_WasntMeLink_LocksAccountAndSendsConfirmation()
    {
        // arrange
        var user = await RegisterAndConfirmUserAsync();
        var loginToken = await LoginAsync(user);

        AuthClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", loginToken.Value);

        // Clear inbox so the password-changed email is the only message we see — the
        // registration-confirmation email would otherwise be the "first match".
        await SmtpClient.ClearAsync();

        var newPassword = "NewP@ssw0rd9876";

        // act — phase 1: change password
        var changeResponse = await AuthClient.PostAsJsonAsync(
            "/api/Account/changepassword",
            new ChangePasswordDto
            {
                OldPassword = user.Password,
                NewPassword = newPassword,
                ConfirmPassword = newPassword,
            });

        // assert — phase 1
        changeResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "a password change with the correct old password must succeed.");

        var changedEmail = await SmtpClient.WaitForMessageAsync(user.Email, TimeSpan.FromSeconds(10));
        changedEmail.Should().NotBeNull();
        changedEmail!.Subject.Should().Be(EmailSubjects.PasswordChanged);

        var body = await SmtpClient.GetMessageHtmlAsync(changedEmail.Id);
        var lockLink = MailLinkExtractor.FindLinkContaining(body, PageRouteConstants.LockAccount);
        lockLink.Should().NotBeNull(
            because: "the password-changed email body must contain a 'wasn't me' link pointing at the lock-account page.");

        // Bypass the LockAccount Razor page and POST directly to the API — the endpoint
        // is the actual contract.
        var query = QueryHelpers.ParseQuery(lockLink!.Query);
        var lockToken = query["token"].ToString();
        var lockEmail = query["email"].ToString();
        lockToken.Should().NotBeNullOrWhiteSpace();
        lockEmail.Should().Be(user.Email);

        // The change-password call rotated the security stamp; our existing Bearer
        // token is dead. /lock is anonymous — drop the header to avoid ambiguity.
        AuthClient.DefaultRequestHeaders.Authorization = null;

        // Clear inbox so the next wait-for-email sees only the post-lock confirmation.
        await SmtpClient.ClearAsync();

        // act — phase 2: "wasn't me" lock
        var lockResponse = await AuthClient.PostAsJsonAsync(
            "/api/Account/lock",
            new LockAccountDto { Email = lockEmail, Token = lockToken });

        // assert — phase 2
        lockResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "a valid lockout token from the email must lock the account.");

        // User locked indefinitely (DateTimeOffset.MaxValue) — recovery is via
        // password-reset, which clears LockoutEnd.
        await using (var db = await CreateDbContextAsync())
        {
            var dbUser = await db.Users
                .AsNoTracking()
                .SingleAsync(u => u.Email == user.Email);
            dbUser.LockoutEnd.Should().NotBeNull(
                because: "the lock endpoint sets LockoutEnd to a non-null indefinite value.");
            dbUser.LockoutEnd!.Value.Year.Should().BeGreaterThan(9000,
                because: "the lock endpoint specifically sets DateTimeOffset.MaxValue, distinguishing this from auto-clearing failed-login lockouts.");
        }

        var lockedEmail = await SmtpClient.WaitForMessageAsync(user.Email, TimeSpan.FromSeconds(10));
        lockedEmail.Should().NotBeNull(
            because: "after the panic-button lock fires, the user gets a confirmation email with a reset-password link as the recovery path.");
        lockedEmail!.Subject.Should().Be(EmailSubjects.AccountLocked);
    }
}
