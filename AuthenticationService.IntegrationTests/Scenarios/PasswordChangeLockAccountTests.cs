using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthenticationService.Constants;
using AuthenticationService.Shared.Dtos;
using AwesomeAssertions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// <para><b>Scenario 4 — Password change → "wasn't me!" → account lock.</b></para>
///
/// <para>The "panic button" recovery path. When the auth service notifies a user that
/// their password just changed, the email contains a link the legitimate user can click
/// if it wasn't them — clicking lands on the lockout endpoint and locks the account
/// indefinitely so a hijacker can't keep using the freshly-changed password. Recovery
/// is via the password-reset flow.</para>
///
/// <para>End-to-end this exercises:</para>
/// <list type="bullet">
///   <item><description>POST <c>/changepassword</c> through the JwtBearer pipeline (Bearer token validation + rate limiting + Identity password change)</description></item>
///   <item><description>Email queueing + SMTP dispatch end-to-end</description></item>
///   <item><description>Token-protected URL building (the lockout token is generated via Identity's <c>GenerateUserTokenAsync</c> and validated on the way back in)</description></item>
///   <item><description>Account-lock state persistence in MySQL</description></item>
///   <item><description>Confirmation-of-lock email so the user has visual confirmation the click worked</description></item>
/// </list>
///
/// <para>Specifically catches the kind of regression where someone refactors the link
/// builder or the token-purpose constant and the chain silently breaks — the user would
/// click "wasn't me" expecting their account to lock and nothing would happen.</para>
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class PasswordChangeLockAccountTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task PasswordChange_WasntMeLink_LocksAccountAndSendsConfirmation()
    {
        // arrange — confirmed user, logged in. The change-password call needs a valid
        // Bearer token in the Authorization header, so we capture the login result and
        // attach it to AuthClient.
        var user = await RegisterAndConfirmUserAsync();
        var loginToken = await LoginAsync(user);

        AuthClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", loginToken.Value);

        // Clear the inbox so the password-changed email is the only one we see in act 2.
        // The registration-confirmation email from RegisterAndConfirmUserAsync would
        // otherwise be the "first match" for our user's email and confuse the assertion.
        await SmtpClient.ClearAsync();

        var newPassword = "NewP@ssw0rd9876";

        // act 1 — change the password.
        var changeResponse = await AuthClient.PostAsJsonAsync(
            "/api/Account/changepassword",
            new ChangePasswordDto
            {
                OldPassword = user.Password,
                NewPassword = newPassword,
                ConfirmPassword = newPassword,
            });
        changeResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "a password change with the correct old password must succeed.");

        // act 2 — the password-changed notification email arrives. Subject is
        // EmailSubjects.PasswordChanged; body contains the "wasn't me!" link to the
        // lock-account page (carrying the lockout token in the query string).
        var changedEmail = await SmtpClient.WaitForMessageAsync(user.Email, TimeSpan.FromSeconds(10));
        changedEmail.Should().NotBeNull();
        changedEmail!.Subject.Should().Be(EmailSubjects.PasswordChanged);

        var body = await SmtpClient.GetMessageHtmlAsync(changedEmail.Id);
        var lockLink = MailLinkExtractor.FindLinkContaining(body, PageRouteConstants.LockAccount);
        lockLink.Should().NotBeNull(
            because: "the password-changed email body must contain a 'wasn't me' link pointing at the lock-account page.");

        // act 3 — pull the token + email out of the link's query string. The Razor page
        // (LockAccount.cshtml) would normally render a button that POSTs these to
        // /api/Account/lock; the test bypasses the UI and POSTs directly because the
        // API endpoint is the actual contract.
        var query = QueryHelpers.ParseQuery(lockLink!.Query);
        var lockToken = query["token"].ToString();
        var lockEmail = query["email"].ToString();
        lockToken.Should().NotBeNullOrWhiteSpace();
        lockEmail.Should().Be(user.Email);

        // The change-password call rotated the security stamp via InvalidateUserTokensAsync
        // — our existing Bearer token is dead. /lock is anonymous, so drop the header to
        // avoid any ambiguity.
        AuthClient.DefaultRequestHeaders.Authorization = null;

        // Clear smtp4dev again so the next assertion's "wait for email" sees only the
        // post-lock confirmation, not the still-sitting password-changed message.
        await SmtpClient.ClearAsync();

        // act 4 — POST to /api/Account/lock with the token from the email link.
        var lockResponse = await AuthClient.PostAsJsonAsync(
            "/api/Account/lock",
            new LockAccountDto { Email = lockEmail, Token = lockToken });

        // assert — endpoint succeeded.
        lockResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "a valid lockout token from the email must lock the account.");

        // assert — user is locked in MySQL with DateTimeOffset.MaxValue (indefinite
        // lockout — recovery is via password-reset, which clears LockoutEnd).
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

        // assert — a confirmation email arrived telling the user the lock took effect
        // and offering the password-reset link as the recovery path.
        var lockedEmail = await SmtpClient.WaitForMessageAsync(user.Email, TimeSpan.FromSeconds(10));
        lockedEmail.Should().NotBeNull(
            because: "after the panic-button lock fires, the user gets a confirmation email with a reset-password link as the recovery path.");
        lockedEmail!.Subject.Should().Be(EmailSubjects.AccountLocked);
    }
}
