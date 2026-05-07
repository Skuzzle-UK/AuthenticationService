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
using AuthenticationService.Shared.Enums;
using AuthenticationService.Shared.Models;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// <para>Covers the four AuthenticationController endpoints not exercised in
/// <c>AuthenticationControllerLoginTests</c>:</para>
/// <list type="bullet">
///   <item><description><b>POST /mfa</b> — unknown email, locked, wrong code (records failed attempt + lockout cascade), accepted (token issued + access-failed reset).</description></item>
///   <item><description><b>POST /refresh</b> — invalid expired-token signature 401, every <see cref="RefreshResult"/> case (Success, NotFound, Expired, Reused — Reused triggers the "wasn't me!" notification email + critical SIEM event).</description></item>
///   <item><description><b>POST /logout</b> — missing/invalid sid claim 401, happy path revokes family + access token.</description></item>
///   <item><description><b>POST /logoutall</b> — missing sub 401, orphan-token (sub matches no user) returns Ok after orphan-revoke (idempotent), happy path invalidates all + revokes access token.</description></item>
/// </list>
/// </summary>
public class AuthenticationControllerMfaRefreshLogoutTests
{
    // ─── MFA verify ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Mfa_UnknownEmail_Returns400Generic()
    {
        // arrange
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        // act
        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "ghost@example.com", MfaProvider = MfaProviders.Email, Token = "123456",
        });

        // assert — same generic-400 contract as login: don't tip off attacker which
        // emails are registered.
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Mfa_LockedAccount_Returns401()
    {
        // arrange — account already locked (prior failed attempts pushed the user past
        // the threshold). Even with a valid MFA code, login is denied while locked.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsLockedOutAsync(user).Returns(true);

        // act
        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "alice@example.com", MfaProvider = MfaProviders.Email, Token = "123456",
        });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task Mfa_WrongCode_RecordsFailedAttemptAndReturns401()
    {
        // arrange — user exists, not locked yet, but the supplied code doesn't verify.
        // Counts toward the failed-attempts threshold the same way a wrong password does.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.VerifyMfaTokenAsync(user, MfaProviders.Email.ToString(), "wrong")
            .Returns(false);

        // act
        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "alice@example.com", MfaProvider = MfaProviders.Email, Token = "wrong",
        });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.UserService.Received(1).AccessFailedAsync(user);
    }

    [Fact]
    public async Task Mfa_WrongCode_TripsLockoutThreshold_InvalidatesAndSendsEmail()
    {
        // arrange — wrong code AND that wrong attempt pushed the user over the lockout
        // threshold. Controller cascades: invalidate every active session + send the
        // failed-login lockout notification with the "if it wasn't you, reset now" link.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        // First IsLockedOutAsync (gate at top) returns false; second call (after
        // AccessFailedAsync) returns true. Sequenced returns model the increment.
        deps.UserService.IsLockedOutAsync(user).Returns(false, true);
        deps.UserService.VerifyMfaTokenAsync(user, MfaProviders.Email.ToString(), "wrong")
            .Returns(false);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("reset-tok");

        // act
        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "alice@example.com", MfaProvider = MfaProviders.Email, Token = "wrong",
        });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.UserService.Received(1).AccessFailedAsync(user);
        await deps.UserService.Received(1).InvalidateUserTokensAsync(
            user, Arg.Any<string>(), RevocationReasons.FailedLoginLockout);
        // Lockout email sent.
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com", EmailSubjects.LockedAccountInfo, Arg.Any<string>());
    }

    [Fact]
    public async Task Mfa_AcceptedCode_IssuesTokenAndResetsFailedAttempts()
    {
        // arrange — happy path. Code verifies; a token pair is issued; failed-attempt
        // counter reset so a future wrong password starts the count fresh.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", UserName = "alice" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.VerifyMfaTokenAsync(user, MfaProviders.Email.ToString(), "right")
            .Returns(true);
        deps.UserService.GetRolesAsync(user).Returns((IList<string>)new List<string> { "DefaultUser" });
        var issued = new Token { Type = "Bearer", Value = "eyJ.access" };
        deps.TokenService.CreateTokenAsync(user, Arg.Any<IList<string>>(), Arg.Any<Guid?>(), Arg.Any<string?>())
            .Returns(issued);

        // act
        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "alice@example.com", MfaProvider = MfaProviders.Email, Token = "right",
        });

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Token.Should().BeSameAs(issued);
        await deps.UserService.Received(1).ResetAccessFailedCountAsync(user);
    }

    // ─── Refresh ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_InvalidExpiredTokenSignature_Returns401()
    {
        // arrange — the access token presented in the Authorization header doesn't pass
        // signature/issuer/audience validation (lifetime check is skipped for refresh,
        // but everything else still applies). Reject before going near the refresh-token
        // store.
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.bad");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.bad").Returns(false);

        // act
        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.TokenService.DidNotReceive().RotateRefreshTokenAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task Refresh_Success_Returns200WithNewToken()
    {
        // arrange — happy rotation.
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        var newToken = new Token { Type = "Bearer", Value = "eyJ.new", RefreshToken = "rt-new" };
        deps.TokenService.RotateRefreshTokenAsync("eyJ.access", "rt", Arg.Any<string>())
            .Returns(new RefreshResult.Success(newToken));

        // act
        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Token.Should().BeSameAs(newToken);
    }

    [Fact]
    public async Task Refresh_NotFound_Returns401WithInvalidRefreshTokenMessage()
    {
        // arrange — refresh token never issued (or for a different user).
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        deps.TokenService.RotateRefreshTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(new RefreshResult.NotFound());

        // act
        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "anything" });

        // assert
        var unauthorized = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorized.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.InvalidRefreshToken);
    }

    [Fact]
    public async Task Refresh_Expired_Returns401WithExpiredRefreshTokenMessage()
    {
        // arrange — refresh token row exists but its ExpiresAt has passed.
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        deps.TokenService.RotateRefreshTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(new RefreshResult.Expired());

        // act
        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        // assert — distinct error message so client can prompt re-login (vs. "your token
        // is bad", which might suggest the wrong fix).
        var unauthorized = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorized.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.ExpiredRefreshToken);
    }

    [Fact]
    public async Task Refresh_Reused_NotifiesUserAndReturns401Generic()
    {
        // arrange — refresh-token reuse. Service has already revoked all families +
        // rotated stamp by the time the controller sees this. Controller's job: fire the
        // suspicious-activity email, log Critical SIEM event, return generic 401 (don't
        // tip off attacker).
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        var familyId = Guid.NewGuid();
        deps.TokenService.RotateRefreshTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(new RefreshResult.Reused(familyId));
        deps.TokenService.GetUserId("eyJ.access").Returns("u1");
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByIdAsync("u1").Returns(user);

        // act
        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        // assert — generic 401 + suspicious-activity email sent.
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com", EmailSubjects.SuspiciousActivity, Arg.Any<string>());
    }

    [Fact]
    public async Task Refresh_ReusedButUserHasNoEmail_DoesNotSendEmailButStillReturns401()
    {
        // arrange — reuse cascade fired, but the user record has no email (degenerate
        // case — admin-seeded user with no email, etc.). Controller skips the email send
        // gracefully rather than throwing.
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        deps.TokenService.RotateRefreshTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(new RefreshResult.Reused(Guid.NewGuid()));
        deps.TokenService.GetUserId("eyJ.access").Returns("u1");
        deps.UserService.FindByIdAsync("u1").Returns(new User { Id = "u1", Email = null });

        // act
        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task Refresh_ReusedAndEmailSendThrows_StillReturns401()
    {
        // arrange — security action (revoke + stamp rotation) has already happened. Email
        // send failure must NOT block returning the 401 — that would cascade a transient
        // SMTP outage into refresh-endpoint failures.
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        deps.TokenService.RotateRefreshTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(new RefreshResult.Reused(Guid.NewGuid()));
        deps.TokenService.GetUserId("eyJ.access").Returns("u1");
        deps.UserService.FindByIdAsync("u1").Returns(new User { Id = "u1", Email = "alice@example.com" });
        deps.EmailService
            .When(s => s.SendEmailAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>()))
            .Do(_ => throw new InvalidOperationException("smtp down"));

        // act
        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    // ─── Logout (per-device) ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Logout_MissingSidClaim_Returns401()
    {
        // arrange — sid is the family ID; without it we can't revoke just one device's
        // family. Reject rather than guess.
        var (controller, _) = BuildController(sub: "u1", sid: null);

        // act
        var result = await controller.LogoutAsync();

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task Logout_HappyPath_RevokesFamilyAndAccessToken()
    {
        // arrange
        var familyId = Guid.NewGuid();
        var (controller, deps) = BuildController(sub: "u1", sid: familyId.ToString());
        SetAuthorizationHeader(controller, "eyJ.access");

        // act
        var result = await controller.LogoutAsync();

        // assert
        result.Should().BeOfType<OkObjectResult>();
        await deps.TokenService.Received(1).RevokeFamilyAsync(familyId, RevocationReasons.Logout);
        await deps.TokenService.Received(1).RevokeTokenAsync("eyJ.access", Arg.Any<string>(), RevocationReasons.Logout);
    }

    // ─── Logout (all devices) ───────────────────────────────────────────────────────────

    [Fact]
    public async Task LogoutAll_MissingSubClaim_Returns401()
    {
        // arrange
        var (controller, _) = BuildController(sub: null, sid: Guid.NewGuid().ToString());

        // act
        var result = await controller.LogoutAllAsync();

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task LogoutAll_OrphanToken_RevokesOrphanAndReturnsOkIdempotent()
    {
        // arrange — sub points to a deleted user. Logout-all is idempotent in that case:
        // there's nothing to invalidate (the user is gone), but we still revoke the
        // presented access token so middleware rejects future replays. Returning Ok lets
        // the client move on (calling logout-all repeatedly never errors).
        var (controller, deps) = BuildController(sub: "deleted-user", sid: Guid.NewGuid().ToString());
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.UserService.FindByIdAsync("deleted-user").Returns((User?)null);

        // act
        var result = await controller.LogoutAllAsync();

        // assert
        result.Should().BeOfType<OkObjectResult>();
        await deps.TokenService.Received(1).RevokeOrphanedTokenAsync("eyJ.access", Arg.Any<string>());
        await deps.UserService.DidNotReceive().InvalidateUserTokensAsync(
            Arg.Any<User>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task LogoutAll_HappyPath_InvalidatesEverythingAndRevokesAccessToken()
    {
        // arrange
        var (controller, deps) = BuildController(sub: "u1", sid: Guid.NewGuid().ToString());
        var user = new User { Id = "u1" };
        deps.UserService.FindByIdAsync("u1").Returns(user);
        SetAuthorizationHeader(controller, "eyJ.access");

        // act
        var result = await controller.LogoutAllAsync();

        // assert — InvalidateUserTokensAsync is called WITH the access token argument, so
        // it'll cascade through stamp rotation + family revoke + access-token revoke.
        result.Should().BeOfType<OkObjectResult>();
        await deps.UserService.Received(1).InvalidateUserTokensAsync(
            user, Arg.Any<string>(), RevocationReasons.LogoutAll, "eyJ.access");
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private static (AuthenticationController controller, ControllerDeps deps) BuildController(
        string? sub = "u1", string? sid = null)
    {
        var deps = new ControllerDeps
        {
            EmailService = Substitute.For<IEmailService>(),
            SmsService = Substitute.For<ISmsService>(),
            TokenService = Substitute.For<ITokenService>(),
            UserService = Substitute.For<IUserService>(),
        };

        var controller = new AuthenticationController(
            deps.EmailService, deps.SmsService, deps.TokenService, deps.UserService,
            Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" }),
            NullLogger<AuthenticationController>.Instance);

        var claims = new List<Claim>();
        if (sub is not null) claims.Add(new Claim(ClaimConstants.Sub, sub));
        if (sid is not null) claims.Add(new Claim(ClaimConstants.Sid, sid));

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

    private static void SetAuthorizationHeader(AuthenticationController controller, string token)
        => controller.ControllerContext.HttpContext.Request.Headers.Authorization
            = AuthSchemeConstants.BearerPrefix + token;

    private sealed class ControllerDeps
    {
        public IEmailService EmailService { get; set; } = default!;
        public ISmsService SmsService { get; set; } = default!;
        public ITokenService TokenService { get; set; } = default!;
        public IUserService UserService { get; set; } = default!;
    }
}
