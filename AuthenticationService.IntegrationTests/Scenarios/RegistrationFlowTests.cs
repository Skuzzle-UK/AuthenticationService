using System.Net.Http.Json;
using AuthenticationService.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Models;
using AwesomeAssertions;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// <para><b>Scenario 1 — Register → Confirm Email → Login.</b></para>
///
/// <para>The canonical end-to-end happy path and the most-load-bearing flow in the
/// auth service. Exercises every layer at once: ASP.NET Core middleware → controllers
/// → EF Core → MySQL → QueuedEmailService → SMTP → smtp4dev → and (after the link
/// click) data-protection-protected token validation back through the same stack.</para>
///
/// <para>If this test passes, "the platform fundamentally works." If it ever fails
/// after being green, something serious has regressed at the integration boundary —
/// usually the kind of thing the unit tests' substituted collaborators couldn't have
/// caught.</para>
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class RegistrationFlowTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task Register_ConfirmEmail_Login_FullHappyPath()
    {
        // arrange — fresh user data unique to this test run.
        var email = UniqueEmail();
        var password = "P@ssw0rd1234";  // satisfies the configured Identity password rules
        var registration = new RegistrationDto
        {
            UserName = UniqueUserName(),
            DateOfBirth = new DateOnly(1990, 1, 1),
            Email = email,
            Password = password,
            ConfirmPassword = password,
        };

        // act 1 — register. The controller commits the user inside a transaction and
        // queues a confirmation email; the response is 201 Created with no body.
        var registerResponse = await AuthClient.PostAsJsonAsync(
            "/api/Registration/register",
            registration);

        // assert 1
        registerResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "registration with valid DTO + Identity-conformant password must succeed.");

        // act 2 — wait for the confirmation email to land in smtp4dev. The
        // QueuedEmailService dispatcher pulls from its in-memory channel and pushes via
        // SMTP; typical end-to-end latency is sub-second but we allow up to 10s for CI.
        var message = await SmtpClient.WaitForMessageAsync(email, timeout: TimeSpan.FromSeconds(10));

        // assert 2
        message.Should().NotBeNull(
            because: "registration triggers a confirm-email send via QueuedEmailService.");
        message!.Subject.Should().Be(EmailSubjects.EmailConfirmation,
            because: "the auth service uses this exact subject for confirm-email messages.");

        // act 3 — pull the confirmation link out of the email body. The controller
        // builds it via $"{publicUrl}/api/Registration{ApiRoutes.ConfirmEmail}?…", so we
        // search for that path fragment to find the right link unambiguously.
        var body = await SmtpClient.GetMessageHtmlAsync(message.Id);
        var confirmationLink = MailLinkExtractor.FindLinkContaining(body, "/api/registration/confirm/email");

        // assert 3
        confirmationLink.Should().NotBeNull(
            because: "the email body must contain a confirm-email link for the user to click.");

        // act 4 — "click" the link by issuing a GET. The endpoint validates the token,
        // marks the email confirmed, rotates the security stamp, and 302-redirects to
        // the safe callback URI. AuthClient follows redirects by default; the final
        // landing page is the bundled ActionComplete Razor page (200 OK).
        var confirmResponse = await AuthClient.GetAsync(confirmationLink!);

        // assert 4
        confirmResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "a valid confirmation link confirms the email and lands on the redirect target.");

        // act 5 — try to log in with the now-confirmed account. Pre-confirm, the auth
        // endpoint would have returned 401 EmailNotConfirmed; post-confirm it issues a
        // token pair.
        var loginResponse = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/authenticate",
            new AuthenticationDto { Email = email, Password = password });

        // assert 5
        loginResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "after email confirmation, login with the registration password must succeed.");

        var auth = await loginResponse.Content.ReadFromJsonAsync<AuthenticationResponse>();
        auth.Should().NotBeNull();
        auth!.IsSuccessful.Should().BeTrue();
        auth.Token.Should().NotBeNull(because: "login on a confirmed account must return a token pair.");
        auth.Token!.Value.Should().NotBeNullOrWhiteSpace(because: "the access token is the JWT itself.");
        auth.Token.RefreshToken.Should().NotBeNullOrWhiteSpace(because: "refresh-token rotation needs both halves.");
        auth.MfaRequired.Should().NotBe(true, because: "the registered user has no MFA configured.");
    }
}
