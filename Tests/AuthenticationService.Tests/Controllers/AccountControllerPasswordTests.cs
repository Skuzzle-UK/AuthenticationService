using System.Net;
using System.Security.Claims;
using AuthenticationService.Constants;
using AuthenticationService.Controllers;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// Covers forgot/reset-password, change-password and the panic-button lock endpoints on
/// <see cref="AccountController"/> — the security-critical paths a normal user touches.
/// </summary>
public class AccountControllerPasswordTests
{
    // ─── ForgotPasswordAsync ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ForgotPassword_UnknownEmail_Returns400Generic()
    {
        // Returns 400 generic to avoid leaking registration state. (Returning 200 would be an alternative
        // shape for the same intent — pinned because direction matters for security review.)
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync("ghost@example.com").Returns((User?)null);

        var result = await controller.ForgotPasswordAsync(new ForgotPasswordDto { Email = "ghost@example.com" });

        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ForgotPassword_EmailUnconfirmed_Returns400()
    {
        // Don't send reset link to unverified address — attacker could pre-register a victim's email and intercept.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(false);

        var result = await controller.ForgotPasswordAsync(new ForgotPasswordDto { Email = "alice@example.com" });

        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ForgotPassword_HappyPath_SendsResetEmailWithSuppliedCallback()
    {
        // DTO carries an explicit ResetPasswordUri (consumer's own UI) — link must point at that, not the bundled page.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("reset-token");

        var result = await controller.ForgotPasswordAsync(new ForgotPasswordDto
        {
            Email = "alice@example.com",
            ResetPasswordUri = "https://app.example.com/reset",
        });

        result.Should().BeOfType<OkObjectResult>();
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com",
            EmailSubjects.PasswordReset,
            Arg.Is<string>(body => body.Contains("https://app.example.com/reset")));
    }

    [Fact]
    public async Task ForgotPassword_NoCallbackUri_FallsBackToBundledResetPage()
    {
        // Falls back to PublicUrlSettings.BaseUrl + bundled ResetPassword page.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("reset-token");

        await controller.ForgotPasswordAsync(new ForgotPasswordDto
        {
            Email = "alice@example.com",
            ResetPasswordUri = null,
        });

        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com",
            EmailSubjects.PasswordReset,
            Arg.Is<string>(body =>
                body.Contains($"https://auth.test{PageRouteConstants.ResetPassword}")));
    }

    // ─── ResetForgottenPasswordAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task ResetForgottenPassword_UnknownOrUnconfirmedEmail_Returns400()
    {
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        var result = await controller.ResetForgottenPasswordAsync(new ResetForgottenPasswordDto
        {
            Email = "ghost@example.com",
            Token = MakeBase64UrlToken("reset"),
            NewPassword = "p",
        });

        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.UserService.DidNotReceive()
            .ResetPasswordAsync(Arg.Any<User>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ResetForgottenPassword_IdentityRejectsToken_Returns400WithErrors()
    {
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.ResetPasswordAsync(user, "decoded-tok", "newpass").Returns(
            IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Bad token." }));

        var result = await controller.ResetForgottenPasswordAsync(new ResetForgottenPasswordDto
        {
            Email = "alice@example.com",
            Token = MakeBase64UrlToken("decoded-tok"),
            NewPassword = "newpass",
        });

        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<ApiResponse>()
            .Which.Errors.Should().ContainKey("InvalidToken");
    }

    [Fact]
    public async Task ResetForgottenPassword_HappyPath_InvalidatesTokensClearsLockoutAndNotifies()
    {
        // Reset doubles as account recovery — clears active lockout, invalidates all sessions, sends "wasn't me" panic-button email.
        var (controller, deps) = BuildController();
        var user = new User
        {
            Id = "u1", Email = "alice@example.com",
            LockoutEnd = DateTimeOffset.UtcNow.AddDays(1),
        };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.ResetPasswordAsync(user, "decoded", "newpass").Returns(IdentityResult.Success);
        deps.UserService.GenerateUserTokenAsync(user, Arg.Any<string>(), TokenPurposes.Lockout)
            .Returns("lockout-token");

        var result = await controller.ResetForgottenPasswordAsync(new ResetForgottenPasswordDto
        {
            Email = "alice@example.com",
            Token = MakeBase64UrlToken("decoded"),
            NewPassword = "newpass",
        });

        result.Should().BeOfType<OkObjectResult>();
        await deps.UserService.Received(1).InvalidateUserTokensAsync(
            user, Arg.Any<string>(), RevocationReasons.PasswordReset);
        user.LockoutEnd.Should().BeNull(
            because: "active lockout cleared — endpoint doubles as recovery.");
        await deps.UserService.Received(1).ResetAccessFailedCountAsync(user);
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com", EmailSubjects.PasswordReset,
            Arg.Is<string>(b => b.Contains("lockout-token") || b.Contains("lock your account")));
    }

    // ─── ChangePasswordAsync ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ChangePassword_MissingSubClaim_Returns401()
    {
        var (controller, _) = BuildController(subClaim: null);

        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "old", NewPassword = "new",
        });

        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task ChangePassword_OrphanToken_RevokesAndReturns401()
    {
        var (controller, deps) = BuildController(subClaim: "deleted-user");
        deps.UserService.FindByIdAsync("deleted-user").Returns((User?)null);
        SetAuthorizationHeader(controller, "eyJ.access");

        var result = await controller.ChangePasswordAsync(new ChangePasswordDto());

        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.TokenService.Received(1).RevokeOrphanedTokenAsync("eyJ.access", Arg.Any<string>());
    }

    [Fact]
    public async Task ChangePassword_UnconfirmedEmail_Returns400WithoutRevokingToken()
    {
        // Anomalous (login gates on email confirmed) but token NOT revoked here — comment in source notes
        // future flows might legitimately put a user in this state.
        var (controller, deps) = BuildController(subClaim: "u1");
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByIdAsync("u1").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(false);
        SetAuthorizationHeader(controller, "eyJ.access");

        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "old", NewPassword = "new",
        });

        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.TokenService.DidNotReceive().RevokeOrphanedTokenAsync(Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ChangePassword_LockedAccount_Returns401()
    {
        var (controller, deps) = BuildController(subClaim: "u1");
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByIdAsync("u1").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(true);

        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "old", NewPassword = "new",
        });

        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task ChangePassword_IdentityError_Returns400WithErrors()
    {
        var (controller, deps) = BuildController(subClaim: "u1");
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByIdAsync("u1").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.ChangePasswordAsync(user, "wrong-old", "new").Returns(
            IdentityResult.Failed(new IdentityError { Code = "PasswordMismatch", Description = "Wrong password." }));

        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "wrong-old", NewPassword = "new",
        });

        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<ApiResponse>()
            .Which.Errors.Should().ContainKey("PasswordMismatch");
    }

    [Fact]
    public async Task ChangePassword_HappyPath_InvalidatesEmailsClearsLockoutAndResets()
    {
        var (controller, deps) = BuildController(subClaim: "u1");
        var user = new User
        {
            Id = "u1", Email = "alice@example.com",
            LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(5),
        };
        deps.UserService.FindByIdAsync("u1").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.ChangePasswordAsync(user, "old", "new").Returns(IdentityResult.Success);
        deps.UserService.GenerateUserTokenAsync(user, Arg.Any<string>(), TokenPurposes.Lockout)
            .Returns("lockout-tok");
        SetAuthorizationHeader(controller, "eyJ.access");

        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "old", NewPassword = "new",
        });

        result.Should().BeOfType<OkObjectResult>();
        await deps.UserService.Received(1).InvalidateUserTokensAsync(
            user, Arg.Any<string>(), RevocationReasons.PasswordChange, "eyJ.access");
        user.LockoutEnd.Should().BeNull();
        await deps.UserService.Received(1).ResetAccessFailedCountAsync(user);
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com", EmailSubjects.PasswordChanged, Arg.Any<string>());
    }

    // ─── LockAccountAsync ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task LockAccount_UnknownEmail_Returns400()
    {
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        var result = await controller.LockAccountAsync(new LockAccountDto { Email = "ghost@example.com", Token = "tok" });

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task LockAccount_InvalidToken_Returns401()
    {
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.VerifyUserTokenAsync(user, Arg.Any<string>(), TokenPurposes.Lockout, "bad-tok")
            .Returns(false);

        var result = await controller.LockAccountAsync(new LockAccountDto
        {
            Email = "alice@example.com", Token = "bad-tok",
        });

        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.UserService.DidNotReceive().SetLockoutEnabledAsync(Arg.Any<User>(), Arg.Any<bool>());
    }

    [Fact]
    public async Task LockAccount_HappyPath_InvalidatesLocksIndefinitelyAndSendsResetEmail()
    {
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.VerifyUserTokenAsync(user, Arg.Any<string>(), TokenPurposes.Lockout, "valid-tok")
            .Returns(true);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("reset-token");

        var result = await controller.LockAccountAsync(new LockAccountDto
        {
            Email = "alice@example.com", Token = "valid-tok",
        });

        result.Should().BeOfType<OkObjectResult>();
        await deps.UserService.Received(1).InvalidateUserTokensAsync(
            user, Arg.Any<string>(), RevocationReasons.AccountLock);
        await deps.UserService.Received(1).SetLockoutEnabledAsync(user, true);
        await deps.UserService.Received(1).SetLockoutEndDateAsync(user, LockoutDurations.Indefinite);
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com", EmailSubjects.AccountLocked, Arg.Any<string>());
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private static (AccountController controller, ControllerDeps deps) BuildController(string? subClaim = "user-id-1")
    {
        var deps = new ControllerDeps
        {
            EmailService = Substitute.For<IEmailService>(),
            SmsService = Substitute.For<ISmsService>(),
            TokenService = Substitute.For<ITokenService>(),
            UserService = Substitute.For<IUserService>(),
        };
        var controller = new AccountController(
            deps.EmailService, deps.SmsService, deps.TokenService, deps.UserService,
            Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" }),
            NullLogger<AccountController>.Instance,
            TestMetricsFactory.Create());

        var claims = new List<Claim>();
        if (subClaim is not null) claims.Add(new Claim(ClaimConstants.Sub, subClaim));
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "test")),
                Connection = { RemoteIpAddress = IPAddress.Parse("10.0.0.5") },
            },
        };
        return (controller, deps);
    }

    private static void SetAuthorizationHeader(AccountController controller, string token)
        => controller.ControllerContext.HttpContext.Request.Headers.Authorization
            = AuthSchemeConstants.BearerPrefix + token;

    private static string MakeBase64UrlToken(string raw)
    {
        // Controllers Base64Url-decode before passing to UserManager — tests must ship the same encoding the email link carries.
        return Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(
            System.Text.Encoding.UTF8.GetBytes(raw));
    }

    private sealed class ControllerDeps
    {
        public IEmailService EmailService { get; set; } = default!;
        public ISmsService SmsService { get; set; } = default!;
        public ITokenService TokenService { get; set; } = default!;
        public IUserService UserService { get; set; } = default!;
    }
}
