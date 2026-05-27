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
/// Covers register / confirm-email / resend-confirm / accept-invitation. Uses SQLite InMemory because
/// <c>RegisterUserAsync</c> opens a real DbContext transaction.
/// </summary>
public class RegistrationControllerTests : IDisposable
{
    private readonly List<SqliteConnection> _connections = new();
    private readonly List<DatabaseContext> _contexts = new();

    public void Dispose()
    {
        foreach (var c in _contexts) c.Dispose();
        foreach (var c in _connections) c.Dispose();
        GC.SuppressFinalize(this);
    }

    // ─── Register ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Register_NullBody_Returns400()
    {
        // arrange
        var (controller, _) = BuildController();

        // act
        var result = await controller.RegisterUserAsync(request: null!);

        // assert
        result.Should().BeOfType<BadRequestResult>();
    }

    [Fact]
    public async Task Register_IdentityError_Returns400WithErrors()
    {
        // arrange
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
        await deps.UserService.DidNotReceive().AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>());
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task Register_HappyPath_AssignsRoleSendsConfirmEmailAndReturnsCreated()
    {
        // arrange
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
        // arrange
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
        // arrange
        var (controller, deps) = BuildController();
        deps.UserService.CreateAsync(Arg.Any<User>(), Arg.Any<string>()).Returns(IdentityResult.Success);

        var dto = NewDto();
        dto.PreferredMfaProvider = null;

        // act
        await controller.RegisterUserAsync(dto);

        // assert
        await deps.UserService.DidNotReceive().UpdateAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task Register_ExceptionMidFlow_PropagatesForFrameworkProblemDetails()
    {
        // arrange — AddToRoleAsync throws after CreateAsync succeeded. SendConfirmEmailAsync
        // and CommitAsync come AFTER it in the flow, so neither runs. The transaction
        // rolls back implicitly when `using var transaction` disposes without commit;
        // the exception propagates to the framework's ProblemDetails handler (B2).
        var (controller, deps) = BuildController();
        deps.UserService.CreateAsync(Arg.Any<User>(), Arg.Any<string>()).Returns(IdentityResult.Success);
        deps.UserService.AddToRoleAsync(Arg.Any<User>(), Arg.Any<string>())
            .Returns<Task>(_ => throw new InvalidOperationException("boom"));

        // act + assert
        var act = async () => await controller.RegisterUserAsync(NewDto());

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("boom");
        // Throw short-circuited the flow before SendConfirmEmailAsync ran.
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    // ─── ConfirmEmail (GET) ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task ConfirmEmail_UnknownEmail_Returns400()
    {
        // arrange
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
        // arrange
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
        // arrange
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
        // arrange
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
        // arrange — open-redirect defence: attacker-supplied callback to untrusted domain, fall back to bundled page.
        var (controller, deps) = BuildController(allowedOrigins: new[] { "https://app.example.com" });
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ConfirmEmailAsync(user, "good-tok").Returns(IdentityResult.Success);

        // act
        var result = await controller.ConfirmEmailAsync(
            email: "alice@example.com",
            token: "good-tok",
            callbackUri: "https://attacker.example/phish");

        // assert
        result.Should().BeOfType<RedirectResult>()
            .Which.Url.Should().Be($"https://auth.test{PageRouteConstants.ActionComplete}");
    }

    [Fact]
    public async Task ConfirmEmail_RelativeCallback_IsHonouredAsSafe()
    {
        // arrange — relative URLs stay on the auth-service origin, IsAllowedRedirect treats non-absolute as safe.
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
        // arrange — defensive: don't repeatedly send "please confirm" to an already-confirmed user, low-volume nuisance vector.
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
        // arrange
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
        // arrange — same shape for "no such user" and "token didn't validate" so attacker can't enumerate accounts.
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        // act
        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "ghost@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.UserService.DidNotReceiveWithAnyArgs().ResetPasswordAsync(default!, default!, default!);
    }

    [Fact]
    public async Task AcceptInvitation_UserAlreadyConfirmed_Returns409()
    {
        // arrange — invitation token must not be reusable to reset an established password.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = true, PasswordHash = null };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);

        // act
        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        // assert
        result.Should().BeOfType<ConflictObjectResult>();
        await deps.UserService.DidNotReceiveWithAnyArgs().ResetPasswordAsync(default!, default!, default!);
    }

    [Fact]
    public async Task AcceptInvitation_UserHasPasswordHash_Returns409()
    {
        // arrange — other half of the pending-invitation guard, password already set means invitation has no business overwriting it.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = false, PasswordHash = "existing-hash" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);

        // act
        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        // assert
        result.Should().BeOfType<ConflictObjectResult>();
    }

    [Fact]
    public async Task AcceptInvitation_ResetPasswordFails_ReturnsIdentityErrors()
    {
        // arrange
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = false, PasswordHash = null };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ResetPasswordAsync(user, Arg.Any<string>(), "NewPassword1!")
            .Returns(IdentityResult.Failed(new IdentityError { Code = "PasswordTooShort", Description = "Too short" }));

        // act
        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        // assert
        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<ApiResponse>().Which.Errors.Should().ContainKey("PasswordTooShort");
        user.EmailConfirmed.Should().BeFalse(
            because: "if the password reset failed, we shouldn't flip EmailConfirmed");
    }

    [Fact]
    public async Task AcceptInvitation_HappyPath_FlipsEmailConfirmedAndUpdates()
    {
        // arrange — load-bearing: successful acceptance has to set the password AND mark email confirmed, either omission leaves the user stuck.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = false, PasswordHash = null };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ResetPasswordAsync(user, Arg.Any<string>(), "NewPassword1!")
            .Returns(IdentityResult.Success);

        // act
        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
        });

        // assert
        result.Should().BeOfType<OkObjectResult>();
        user.EmailConfirmed.Should().BeTrue(
            because: "successful invitation accept must mark the user's email as confirmed in one shot");
        await deps.UserService.Received(1).UpdateAsync(user);
    }

    [Fact]
    public async Task AcceptInvitation_HappyPath_WithCallback_ReturnsRedirectPayload()
    {
        // arrange — response body carries `redirect` so the JS form handler can navigate after success.
        var (controller, deps) = BuildController(allowedOrigins: new[] { "https://app.example.com" });
        var user = new User { Id = "u1", Email = "alice@example.com", EmailConfirmed = false, PasswordHash = null };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.ResetPasswordAsync(user, Arg.Any<string>(), Arg.Any<string>()).Returns(IdentityResult.Success);

        // act
        var result = await controller.AcceptInvitationAsync(new AcceptInvitationDto
        {
            Email = "alice@example.com",
            Token = "dGVzdA",
            NewPassword = "NewPassword1!",
            CallbackUri = "https://app.example.com/welcome",
        });

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var redirectProp = ok.Value!.GetType().GetProperty("redirect");
        redirectProp.Should().NotBeNull();
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
