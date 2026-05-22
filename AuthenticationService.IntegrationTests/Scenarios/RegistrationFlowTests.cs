using System.Net.Http.Json;
using AuthenticationService.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Models;
using AwesomeAssertions;

namespace AuthenticationService.IntegrationTests.Scenarios;

/// <summary>
/// Scenario 1 — Register → Confirm Email → Login. The canonical happy path and the most
/// load-bearing flow in the auth service. Exercises middleware → controllers → EF Core
/// → MySQL → QueuedEmailService → SMTP → smtp4dev and back through token validation. If
/// it fails after being green, something serious has regressed at the integration boundary.
/// </summary>
[Collection(IntegrationTestCollection.Name)]
public class RegistrationFlowTests(AppHostFixture fixture) : IntegrationTestBase(fixture)
{
    [Fact]
    public async Task Register_ConfirmEmail_Login_FullHappyPath()
    {
        // arrange
        var email = UniqueEmail();
        var password = "P@ssw0rd1234";
        var registration = new RegistrationDto
        {
            UserName = UniqueUserName(),
            DateOfBirth = new DateOnly(1990, 1, 1),
            Email = email,
            Password = password,
            ConfirmPassword = password,
        };

        // act — phase 1: register
        var registerResponse = await AuthClient.PostAsJsonAsync(
            "/api/Registration/register",
            registration);

        // assert — phase 1
        registerResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "registration with valid DTO + Identity-conformant password must succeed.");

        var message = await SmtpClient.WaitForMessageAsync(email, timeout: TimeSpan.FromSeconds(10));

        message.Should().NotBeNull(
            because: "registration triggers a confirm-email send via QueuedEmailService.");
        message!.Subject.Should().Be(EmailSubjects.EmailConfirmation,
            because: "the auth service uses this exact subject for confirm-email messages.");

        var body = await SmtpClient.GetMessageHtmlAsync(message.Id);
        var confirmationLink = MailLinkExtractor.FindLinkContaining(body, "/api/registration/confirm/email");

        confirmationLink.Should().NotBeNull(
            because: "the email body must contain a confirm-email link for the user to click.");

        // act — phase 2: confirm email
        // "Click" the link — endpoint validates the token, marks email confirmed,
        // rotates security stamp, 302-redirects to the ActionComplete Razor page.
        var confirmResponse = await AuthClient.GetAsync(confirmationLink!);

        // assert — phase 2
        confirmResponse.IsSuccessStatusCode.Should().BeTrue(
            because: "a valid confirmation link confirms the email and lands on the redirect target.");

        // act — phase 3: login
        var loginResponse = await AuthClient.PostAsJsonAsync(
            "/api/Authentication/authenticate",
            new AuthenticationDto { Email = email, Password = password });

        // assert — phase 3
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
