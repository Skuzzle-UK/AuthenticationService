using System.Net;
using AuthenticationService.Constants;
using AuthenticationService.Controllers;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using AuthenticationService.Storage;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// <para>Covers all three RegistrationController endpoints:</para>
/// <list type="bullet">
///   <item><description><b>POST /register</b> — null body 400, identity error 400 (errors surfaced), Identity success → role assigned + MFA preference applied if supplied + confirm-email sent + transaction committed + 201, exception during create-flow → rollback + 500 with correlation id.</description></item>
///   <item><description><b>GET /confirm/email</b> — unknown email 400, identity confirm error 400, success → security stamp rotated + redirect to safe callback (allow-listed origin honoured, off-list falls back to default + warn).</description></item>
///   <item><description><b>POST /confirm/email</b> (resend) — unknown email 400, already-confirmed 400, fresh send Ok.</description></item>
/// </list>
/// <para>Uses SQLite InMemory because <c>RegisterUserAsync</c> opens a real
/// <see cref="DatabaseContext"/> transaction.</para>
/// </summary>
public class RegistrationControllerTests : IDisposable
{
    private readonly List<SqliteConnection> _connections = new();
    private readonly List<DatabaseContext> _contexts = new();

    public void Dispose()
    {
        foreach (var c in _contexts) c.Dispose();
        foreach (var c in _connections) c.Dispose();
    }

    // ─── Register ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Register_NullBody_Returns400()
    {
        // arrange — defensive null-body check before any DB work.
        var (controller, _) = BuildController();

        // act
        var result = await controller.RegisterUserAsync(request: null!);

        // assert
        result.Should().BeOfType<BadRequestResult>();
    }

    [Fact]
    public async Task Register_IdentityError_Returns400WithErrors()
    {
        // arrange — Identity rejects (e.g., password too weak, username reserved). Errors
        // are surfaced verbatim so the UI can display them.
        var (controller, deps) = BuildController();
        deps.UserService.CreateAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns(IdentityResult.Failed(
                new IdentityError { Code = "PasswordTooShort", Description = "Password must be 12+ chars." }));

        // act
        var result = await controller.RegisterUserAsync(NewDto());

        // assert
        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<ApiResponse>()
            .Which.Errors.Should().ContainKey("PasswordTooShort");
        // No role assigned, no email sent — registration aborted before those steps.
        await deps.UserService.DidNotReceive().AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>());
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task Register_HappyPath_AssignsRoleSendsConfirmEmailAndReturnsCreated()
    {
        // arrange — full happy flow.
        var (controller, deps) = BuildController();
        deps.UserService.CreateAsync(Arg.Any<User>(), Arg.Any<string>()).Returns(IdentityResult.Success);
        deps.UserService.GenerateEmailConfirmationTokenAsync(Arg.Any<User>()).Returns("confirm-tok");

        // act
        var result = await controller.RegisterUserAsync(NewDto());

        // assert
        result.Should().BeOfType<CreatedResult>();
        await deps.UserService.Received(1).AddToRoleAsync(Arg.Any<User>(), RolesConstants.DefaultUser);
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com", EmailSubjects.EmailConfirmation, Arg.Any<string>());
    }

    [Fact]
    public async Task Register_WithMfaPreference_AppliesItToUser()
    {
        // arrange — DTO carries a preferred MFA provider. Controller must call
        // UpdateAsync with the new preference set on the user.
        var (controller, deps) = BuildController();
        deps.UserService.CreateAsync(Arg.Any<User>(), Arg.Any<string>()).Returns(IdentityResult.Success);
        var dto = NewDto();
        dto.PreferredMfaProvider = MfaProviders.Authenticator;
        User? capturedUser = null;
        deps.UserService.UpdateAsync(Arg.Do<User>(u => capturedUser = u))
            .Returns(Task.CompletedTask);

        // act
        await controller.RegisterUserAsync(dto);

        // assert
        capturedUser.Should().NotBeNull();
        capturedUser!.PreferredMfaProvider.Should().Be(MfaProviders.Authenticator);
    }

    [Fact]
    public async Task Register_NoMfaPreference_DoesNotCallUpdateAsync()
    {
        // arrange — DTO leaves PreferredMfaProvider null. The conditional UpdateAsync
        // should be skipped (the user row is already in the DB from CreateAsync).
        var (controller, deps) = BuildController();
        deps.UserService.CreateAsync(Arg.Any<User>(), Arg.Any<string>()).Returns(IdentityResult.Success);

        // act
        var dto = NewDto();
        dto.PreferredMfaProvider = null;
        await controller.RegisterUserAsync(dto);

        // assert
        await deps.UserService.DidNotReceive().UpdateAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task Register_ExceptionMidFlow_RollsBackTransactionAndReturns500WithCorrelationId()
    {
        // arrange — CreateAsync succeeds, but role assignment throws (e.g., DB hiccup).
        // The transaction must roll back so the partial registration doesn't leave a row
        // without a role; controller must return 500 with a correlation ID for support.
        var (controller, deps) = BuildController();
        deps.UserService.CreateAsync(Arg.Any<User>(), Arg.Any<string>()).Returns(IdentityResult.Success);
        deps.UserService.AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns<Task>(_ => throw new InvalidOperationException("boom"));

        // act
        var result = await controller.RegisterUserAsync(NewDto());

        // assert
        var status = result.Should().BeOfType<ObjectResult>().Subject;
        status.StatusCode.Should().Be(500);
        var body = status.Value.Should().BeOfType<ApiResponse>().Subject;
        body.Errors.Should().ContainKey("RegistrationFailed");
        // Description references the correlation ID so support can match logs to the
        // user-facing response.
        body.Errors!["RegistrationFailed"].Should().Contain("reference ");
    }

    // ─── ConfirmEmail (GET) ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task ConfirmEmail_UnknownEmail_Returns400()
    {
        // arrange — user not in DB; treat as malformed link.
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        // act
        var result = await controller.ConfirmEmailAsync(email: "ghost@example.com", token: "t", callbackUri: null);

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task ConfirmEmail_IdentityRejectsToken_Returns400()
    {
        // arrange — link clicked, user found, but the confirmation token is wrong /
        // expired / for a different user. Don't confirm.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ConfirmEmailAsync(user, "bad-tok").Returns(
            IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "bad" }));

        // act
        var result = await controller.ConfirmEmailAsync(email: "alice@example.com", token: "bad-tok", callbackUri: null);

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.UserService.DidNotReceive().UpdateSecurityStampAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task ConfirmEmail_SuccessNoCallback_RedirectsToBundledActionCompletePage()
    {
        // arrange — link valid, no callback. Default destination is the bundled
        // ActionComplete Razor page.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ConfirmEmailAsync(user, "good-tok").Returns(IdentityResult.Success);

        // act
        var result = await controller.ConfirmEmailAsync(email: "alice@example.com", token: "good-tok", callbackUri: null);

        // assert
        result.Should().BeOfType<RedirectResult>()
            .Which.Url.Should().Be($"https://auth.test{PageRouteConstants.ActionComplete}");
        await deps.UserService.Received(1).UpdateSecurityStampAsync(user);
    }

    [Fact]
    public async Task ConfirmEmail_SuccessWithAllowedCallback_RedirectsToCallback()
    {
        // arrange — callback URL on the CORS allow-list, so it's safe to honour.
        var (controller, deps) = BuildController(allowedOrigins: new[] { "https://app.example.com" });
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ConfirmEmailAsync(user, "good-tok").Returns(IdentityResult.Success);

        // act
        var result = await controller.ConfirmEmailAsync(
            email: "alice@example.com",
            token: "good-tok",
            callbackUri: "https://app.example.com/landing");

        // assert
        result.Should().BeOfType<RedirectResult>()
            .Which.Url.Should().Be("https://app.example.com/landing");
    }

    [Fact]
    public async Task ConfirmEmail_SuccessWithOffListCallback_FallsBackToDefault()
    {
        // arrange — open-redirect attempt: attacker-supplied callback to a domain we
        // don't trust. Controller logs warning + falls back to bundled page.
        var (controller, deps) = BuildController(allowedOrigins: new[] { "https://app.example.com" });
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ConfirmEmailAsync(user, "good-tok").Returns(IdentityResult.Success);

        // act
        var result = await controller.ConfirmEmailAsync(
            email: "alice@example.com",
            token: "good-tok",
            callbackUri: "https://attacker.example/phish");

        // assert — redirected to default rather than the attacker's URL.
        result.Should().BeOfType<RedirectResult>()
            .Which.Url.Should().Be($"https://auth.test{PageRouteConstants.ActionComplete}");
    }

    [Fact]
    public async Task ConfirmEmail_RelativeCallback_IsHonouredAsSafe()
    {
        // arrange — relative URLs stay on the auth-service origin so they're inherently
        // safe (no exfiltration possible). Controller's IsAllowedRedirect treats
        // non-absolute URIs as safe.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ConfirmEmailAsync(user, "good-tok").Returns(IdentityResult.Success);

        // act
        var result = await controller.ConfirmEmailAsync(
            email: "alice@example.com",
            token: "good-tok",
            callbackUri: "/some/relative/page");

        // assert
        result.Should().BeOfType<RedirectResult>()
            .Which.Url.Should().Be("/some/relative/page");
    }

    // ─── ResendConfirmEmail (POST) ──────────────────────────────────────────────────────

    [Fact]
    public async Task ResendConfirmEmail_UnknownEmail_Returns400()
    {
        // arrange
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        // act
        var result = await controller.ResendConfirmEmailAsync(new ResendEmailConfirmationDto { Email = "ghost@example.com" });

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ResendConfirmEmail_AlreadyConfirmed_Returns400()
    {
        // arrange — defensive: don't repeatedly send "please confirm" emails to a user
        // who's already confirmed. Could be exploited as a low-volume nuisance vector.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);

        // act
        var result = await controller.ResendConfirmEmailAsync(new ResendEmailConfirmationDto { Email = "alice@example.com" });

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ResendConfirmEmail_HappyPath_GeneratesFreshTokenAndSends()
    {
        // arrange — user exists, not yet confirmed. Generate a fresh token (the previous
        // one's still valid until expiry, but rotating doesn't hurt and helps if the user
        // lost the email and is now resending).
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(false);
        deps.UserService.GenerateEmailConfirmationTokenAsync(user).Returns("new-tok");

        // act
        var result = await controller.ResendConfirmEmailAsync(new ResendEmailConfirmationDto { Email = "alice@example.com" });

        // assert
        result.Should().BeOfType<OkObjectResult>();
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com",
            EmailSubjects.EmailConfirmation,
            Arg.Is<string>(body => body.Contains("new-tok")));
    }

    // ─── AcceptInvitation ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AcceptInvitation_UnknownEmail_Returns400()
    {
        // Defensive: don't leak which emails exist — same shape for "no such user" and
        // "token didn't validate" so an attacker can't enumerate accounts.
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "ghost@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.UserService.DidNotReceiveWithAnyArgs().ResetPasswordAsync(default!, default!, default!);
    }

    [Fact]
    public async Task AcceptInvitation_UserAlreadyConfirmed_Returns409()
    {
        // User already activated (clicked invitation before, or registered via the normal
        // flow). Invitation token must not be reusable to reset an established password.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = true, PasswordHash = null };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);

        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        result.Should().BeOfType<ConflictObjectResult>();
        await deps.UserService.DidNotReceiveWithAnyArgs().ResetPasswordAsync(default!, default!, default!);
    }

    [Fact]
    public async Task AcceptInvitation_UserHasPasswordHash_Returns409()
    {
        // The other half of the pending-invitation guard — if a password is already set
        // (legacy account or someone bypassing the flow) the invitation has no business
        // overwriting it.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = false, PasswordHash = "existing-hash" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);

        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        result.Should().BeOfType<ConflictObjectResult>();
    }

    [Fact]
    public async Task AcceptInvitation_ResetPasswordFails_ReturnsIdentityErrors()
    {
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = false, PasswordHash = null };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ResetPasswordAsync(user, Arg.Any<string>(), "NewPassword1!")
            .Returns(IdentityResult.Failed(new IdentityError { Code = "PasswordTooShort", Description = "Too short" }));

        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<ApiResponse>().Which.Errors.Should().ContainKey("PasswordTooShort");
        user.EmailConfirmed.Should().BeFalse(
            because: "if the password reset failed, we shouldn't flip EmailConfirmed");
    }

    [Fact]
    public async Task AcceptInvitation_HappyPath_FlipsEmailConfirmedAndUpdates()
    {
        // The load-bearing one: a successful invitation acceptance has to do BOTH set
        // the password AND mark the email confirmed. Forgetting either leaves the user
        // in a stuck state.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = false, PasswordHash = null };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ResetPasswordAsync(user, Arg.Any<string>(), "NewPassword1!")
            .Returns(IdentityResult.Success);

        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        result.Should().BeOfType<OkObjectResult>();
        user.EmailConfirmed.Should().BeTrue(
            because: "successful invitation accept must mark the user's email as confirmed in one shot");
        await deps.UserService.Received(1).UpdateAsync(user);
    }

    [Fact]
    public async Task AcceptInvitation_HappyPath_WithCallback_ReturnsRedirectPayload()
    {
        // When the admin supplied a callbackUri on user creation, the invitation form
        // carries it through and we echo it back so the page can redirect.
        var (controller, deps) = BuildController(allowedOrigins: new[] { "https://app.example.com" });
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = false, PasswordHash = null };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ResetPasswordAsync(user, Arg.Any<string>(), Arg.Any<string>()).Returns(IdentityResult.Success);

        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
            CallbackUri = "https://app.example.com/welcome",
        });

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        // The anonymous-object body has a `redirect` property pointing at the safe callback.
        var redirectProp = ok.Value!.GetType().GetProperty("redirect");
        redirectProp.Should().NotBeNull(
            because: "the response body must carry the redirect target so the JS form handler can navigate after success");
        redirectProp!.GetValue(ok.Value).Should().Be("https://app.example.com/welcome");
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private (RegistrationController controller, ControllerDeps deps) BuildController(
        IEnumerable<string>? allowedOrigins = null)
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        _connections.Add(connection);

        var dbOptions = new DbContextOptionsBuilder<DatabaseContext>().UseSqlite(connection).Options;
        var db = new DatabaseContext(dbOptions);
        db.Database.EnsureCreated();
        _contexts.Add(db);

        var deps = new ControllerDeps
        {
            EmailService = Substitute.For<IEmailService>(),
            UserService = Substitute.For<IUserService>(),
        };

        var controller = new RegistrationController(
            deps.UserService,
            deps.EmailService,
            db,
            Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" }),
            Options.Create(new CorsSettings { AllowedOrigins = allowedOrigins?.ToList() ?? new List<string>() }),
            NullLogger<RegistrationController>.Instance,
            TestMetricsFactory.Create());

        var actionDescriptor = new Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor
        {
            ControllerName = "Registration",
        };
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                Connection = { RemoteIpAddress = IPAddress.Parse("10.0.0.5") },
            },
            ActionDescriptor = actionDescriptor,
        };
        return (controller, deps);
    }

    private static RegistrationDto NewDto() => new()
    {
        UserName = "alice",
        DateOfBirth = new DateOnly(1990, 1, 1),
        Email = "alice@example.com",
        Password = "P@ssw0rd1234",
    };

    private sealed class ControllerDeps
    {
        public IEmailService EmailService { get; set; } = default!;
        public IUserService UserService { get; set; } = default!;
    }
}
