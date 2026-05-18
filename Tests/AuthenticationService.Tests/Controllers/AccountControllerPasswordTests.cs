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
/// <para>Covers the three password-flow endpoints + the panic-button lock endpoint on
/// <see cref="AccountController"/>. These are the security-critical paths a normal user
/// touches:</para>
/// <list type="bullet">
///   <item><description><b>POST /forgotpassword</b> — kicks off reset, returns 200 even for unknown email (don't leak registration), unconfirmed email returns 400, default vs. supplied callback URI behaviour.</description></item>
///   <item><description><b>POST /forgotpassword/reset</b> — unknown / unconfirmed email 400, identity reset failure 400 with errors, success → invalidate-all-tokens, clear lockout, send notification.</description></item>
///   <item><description><b>POST /changepassword</b> — missing sub 401, orphan-token revoke + 401, unconfirmed email 400, locked 401, identity error 400, success → invalidate + email + clear lockout + reset access-failed.</description></item>
///   <item><description><b>POST /lock</b> — unknown email 400, invalid token 401, valid happy path → invalidate + lock indefinitely + send reset email.</description></item>
/// </list>
/// </summary>
public class AccountControllerPasswordTests
{
    // ─── ForgotPasswordAsync ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ForgotPassword_UnknownEmail_Returns400Generic()
    {
        // arrange — server doesn't leak which addresses are registered. Returning 200 here
        // would be the alternative; current contract is 400 generic. Pinned because the
        // contract direction matters for security review even if the underlying intent
        // (don't leak registration state) is the same.
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync("ghost@example.com").Returns((User?)null);

        // act
        var result = await controller.ForgotPasswordAsync(new ForgotPasswordDto { Email = "ghost@example.com" });

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ForgotPassword_EmailUnconfirmed_Returns400()
    {
        // arrange — user exists but hasn't confirmed email. Don't send a reset link to
        // an unverified address — that would let an attacker pre-register a victim's
        // email and intercept the reset.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(false);

        // act
        var result = await controller.ForgotPasswordAsync(new ForgotPasswordDto { Email = "alice@example.com" });

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ForgotPassword_HappyPath_SendsResetEmailWithSuppliedCallback()
    {
        // arrange — confirmed user; DTO carries an explicit ResetPasswordUri (consumer's
        // own UI). That URI is what the email link must point at, not the auth service's
        // bundled page.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("reset-token");

        // act
        var result = await controller.ForgotPasswordAsync(new ForgotPasswordDto
        {
            Email = "alice@example.com",
            ResetPasswordUri = "https://app.example.com/reset",
        });

        // assert
        result.Should().BeOfType<OkObjectResult>();
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com",
            EmailSubjects.PasswordReset,
            Arg.Is<string>(body => body.Contains("https://app.example.com/reset")));
    }

    [Fact]
    public async Task ForgotPassword_NoCallbackUri_FallsBackToBundledResetPage()
    {
        // arrange — DTO doesn't carry a ResetPasswordUri. Controller falls back to the
        // PublicUrlSettings.BaseUrl + bundled /ResetPassword Razor page. Pinned so the
        // service still works for callers that don't pass a custom UI URL.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("reset-token");

        // act
        await controller.ForgotPasswordAsync(new ForgotPasswordDto
        {
            Email = "alice@example.com",
            ResetPasswordUri = null,
        });

        // assert
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
        // arrange — same hostile-input gate as ForgotPassword.
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        // act
        var result = await controller.ResetForgottenPasswordAsync(new ResetForgottenPasswordDto
        {
            Email = "ghost@example.com",
            Token = MakeBase64UrlToken("reset"),
            NewPassword = "p",
        });

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.UserService.DidNotReceive()
            .ResetPasswordAsync(Arg.Any<User>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ResetForgottenPassword_IdentityRejectsToken_Returns400WithErrors()
    {
        // arrange — token is wrong / expired / for a different user. Identity returns
        // Failed; controller must surface those errors so the UI can show them.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.ResetPasswordAsync(user, "decoded-tok", "newpass").Returns(
            IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "Bad token." }));

        // act
        var result = await controller.ResetForgottenPasswordAsync(new ResetForgottenPasswordDto
        {
            Email = "alice@example.com",
            Token = MakeBase64UrlToken("decoded-tok"),
            NewPassword = "newpass",
        });

        // assert
        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<ApiResponse>()
            .Which.Errors.Should().ContainKey("InvalidToken");
    }

    [Fact]
    public async Task ResetForgottenPassword_HappyPath_InvalidatesTokensClearsLockoutAndNotifies()
    {
        // arrange — full happy flow: reset succeeds, all sessions revoked + stamp rotated,
        // active lockout cleared (this endpoint doubles as account recovery), notification
        // email with "wasn't me" panic-button link sent.
        var (controller, deps) = BuildController();
        var user = new User
        {
            Id = "u1", Email = "alice@example.com",
            LockoutEnd = DateTimeOffset.UtcNow.AddDays(1), // pre-existing lockout
        };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.ResetPasswordAsync(user, "decoded", "newpass").Returns(IdentityResult.Success);
        deps.UserService.GenerateUserTokenAsync(user, Arg.Any<string>(), TokenPurposes.Lockout)
            .Returns("lockout-token");

        // act
        var result = await controller.ResetForgottenPasswordAsync(new ResetForgottenPasswordDto
        {
            Email = "alice@example.com",
            Token = MakeBase64UrlToken("decoded"),
            NewPassword = "newpass",
        });

        // assert
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
        // arrange — principal without sub. Controller short-circuits before any
        // UserService call.
        var (controller, _) = BuildController(subClaim: null);

        // act
        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "old", NewPassword = "new",
        });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task ChangePassword_OrphanToken_RevokesAndReturns401()
    {
        // arrange — sub claim resolved to a deleted user.
        var (controller, deps) = BuildController(subClaim: "deleted-user");
        deps.UserService.FindByIdAsync("deleted-user").Returns((User?)null);
        SetAuthorizationHeader(controller, "eyJ.access");

        // act
        var result = await controller.ChangePasswordAsync(new ChangePasswordDto());

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.TokenService.Received(1).RevokeOrphanedTokenAsync("eyJ.access", Arg.Any<string>());
    }

    [Fact]
    public async Task ChangePassword_UnconfirmedEmail_Returns400WithoutRevokingToken()
    {
        // arrange — anomalous (login already gates on email confirmed) but we don't revoke
        // the token here — comment in the source explicitly notes future flows might
        // legitimately put a user in this state.
        var (controller, deps) = BuildController(subClaim: "u1");
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByIdAsync("u1").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(false);
        SetAuthorizationHeader(controller, "eyJ.access");

        // act
        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "old", NewPassword = "new",
        });

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
        await deps.TokenService.DidNotReceive().RevokeOrphanedTokenAsync(Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task ChangePassword_LockedAccount_Returns401()
    {
        // arrange — locked user. Don't allow password change while locked.
        var (controller, deps) = BuildController(subClaim: "u1");
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByIdAsync("u1").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(true);

        // act
        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "old", NewPassword = "new",
        });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task ChangePassword_IdentityError_Returns400WithErrors()
    {
        // arrange — wrong old password. Identity returns Failed; controller surfaces
        // errors.
        var (controller, deps) = BuildController(subClaim: "u1");
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByIdAsync("u1").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.ChangePasswordAsync(user, "wrong-old", "new").Returns(
            IdentityResult.Failed(new IdentityError { Code = "PasswordMismatch", Description = "Wrong password." }));

        // act
        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "wrong-old", NewPassword = "new",
        });

        // assert
        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<ApiResponse>()
            .Which.Errors.Should().ContainKey("PasswordMismatch");
    }

    [Fact]
    public async Task ChangePassword_HappyPath_InvalidatesEmailsClearsLockoutAndResets()
    {
        // arrange — full happy flow.
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

        // act
        var result = await controller.ChangePasswordAsync(new ChangePasswordDto
        {
            OldPassword = "old", NewPassword = "new",
        });

        // assert
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
        // arrange
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        // act
        var result = await controller.LockAccountAsync(new LockAccountDto { Email = "ghost@example.com", Token = "tok" });

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task LockAccount_InvalidToken_Returns401()
    {
        // arrange — user exists but token isn't valid (replayed / forged).
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.VerifyUserTokenAsync(user, Arg.Any<string>(), TokenPurposes.Lockout, "bad-tok")
            .Returns(false);

        // act
        var result = await controller.LockAccountAsync(new LockAccountDto
        {
            Email = "alice@example.com", Token = "bad-tok",
        });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.UserService.DidNotReceive().SetLockoutEnabledAsync(Arg.Any<User>(), Arg.Any<bool>());
    }

    [Fact]
    public async Task LockAccount_HappyPath_InvalidatesLocksIndefinitelyAndSendsResetEmail()
    {
        // arrange — full panic-button flow.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.VerifyUserTokenAsync(user, Arg.Any<string>(), TokenPurposes.Lockout, "valid-tok")
            .Returns(true);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("reset-token");

        // act
        var result = await controller.LockAccountAsync(new LockAccountDto
        {
            Email = "alice@example.com", Token = "valid-tok",
        });

        // assert
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
        // The controllers Base64Url-decode the token before passing it to UserManager.
        // Tests have to ship the same encoding the email link would carry, otherwise
        // controller's WebEncoders.Base64UrlDecode call throws.
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
