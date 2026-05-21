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
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// Covers MFA verify, refresh (every <see cref="RefreshResult"/> case incl. Reused cascade),
/// per-device logout, and logout-all (incl. orphan-token idempotency).
/// </summary>
public class AuthenticationControllerMfaRefreshLogoutTests
{
    // ─── MFA verify ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Mfa_UnknownEmail_Returns400Generic()
    {
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "ghost@example.com", MfaProvider = MfaProviders.Email, Token = "123456",
        });

        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Mfa_LockedAccount_Returns401()
    {
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsLockedOutAsync(user).Returns(true);

        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "alice@example.com", MfaProvider = MfaProviders.Email, Token = "123456",
        });

        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task Mfa_WrongCode_RecordsFailedAttemptAndReturns401()
    {
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.VerifyMfaTokenAsync(user, MfaProviders.Email.ToString(), "wrong")
            .Returns(false);

        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "alice@example.com", MfaProvider = MfaProviders.Email, Token = "wrong",
        });

        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.UserService.Received(1).AccessFailedAsync(user);
    }

    [Fact]
    public async Task Mfa_WrongCode_TripsLockoutThreshold_InvalidatesAndSendsEmail()
    {
        // Wrong code pushes user over lockout threshold — controller cascades: invalidate sessions + send lockout email.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        // Sequenced returns: first call (gate) false, second call (after AccessFailedAsync) true.
        deps.UserService.IsLockedOutAsync(user).Returns(false, true);
        deps.UserService.VerifyMfaTokenAsync(user, MfaProviders.Email.ToString(), "wrong")
            .Returns(false);
        deps.UserService.GeneratePasswordResetTokenAsync(user).Returns("reset-tok");

        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "alice@example.com", MfaProvider = MfaProviders.Email, Token = "wrong",
        });

        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.UserService.Received(1).AccessFailedAsync(user);
        await deps.UserService.Received(1).InvalidateUserTokensAsync(
            user, Arg.Any<string>(), RevocationReasons.FailedLoginLockout);
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com", EmailSubjects.LockedAccountInfo, Arg.Any<string>());
    }

    [Fact]
    public async Task Mfa_AcceptedCode_IssuesTokenAndResetsFailedAttempts()
    {
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

        var result = await controller.MfaAuthenticateAsync(new MfaAuthenticationDto
        {
            Email = "alice@example.com", MfaProvider = MfaProviders.Email, Token = "right",
        });

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Token.Should().BeSameAs(issued);
        await deps.UserService.Received(1).ResetAccessFailedCountAsync(user);
    }

    // ─── Refresh ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_InvalidExpiredTokenSignature_Returns401()
    {
        // Access-token signature/issuer/audience fails — reject before going near the refresh store.
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.bad");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.bad").Returns(false);

        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.TokenService.DidNotReceive().RotateRefreshTokenAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task Refresh_Success_Returns200WithNewToken()
    {
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        var newToken = new Token { Type = "Bearer", Value = "eyJ.new", RefreshToken = "rt-new" };
        deps.TokenService.RotateRefreshTokenAsync("eyJ.access", "rt", Arg.Any<string>())
            .Returns(new RefreshResult.Success(newToken));

        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Token.Should().BeSameAs(newToken);
    }

    [Fact]
    public async Task Refresh_NotFound_Returns401WithInvalidRefreshTokenMessage()
    {
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        deps.TokenService.RotateRefreshTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(new RefreshResult.NotFound());

        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "anything" });

        var unauthorized = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorized.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.InvalidRefreshToken);
    }

    [Fact]
    public async Task Refresh_Expired_Returns401WithExpiredRefreshTokenMessage()
    {
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        deps.TokenService.RotateRefreshTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(new RefreshResult.Expired());

        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        // Distinct error message so client can prompt re-login rather than retry with a different token.
        var unauthorized = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorized.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.ExpiredRefreshToken);
    }

    [Fact]
    public async Task Refresh_Reused_NotifiesUserAndReturns401Generic()
    {
        // Reuse detected — service already revoked families and rotated stamp. Controller sends suspicious-activity email + generic 401.
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        var familyId = Guid.NewGuid();
        deps.TokenService.RotateRefreshTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(new RefreshResult.Reused(familyId));
        deps.TokenService.GetUserId("eyJ.access").Returns("u1");
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByIdAsync("u1").Returns(user);

        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com", EmailSubjects.SuspiciousActivity, Arg.Any<string>());
    }

    [Fact]
    public async Task Refresh_ReusedButUserHasNoEmail_DoesNotSendEmailButStillReturns401()
    {
        // Degenerate case — admin-seeded user with no email. Controller skips email send gracefully.
        var (controller, deps) = BuildController();
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.TokenService.ValidateExpiredTokenAsync("eyJ.access").Returns(true);
        deps.TokenService.RotateRefreshTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(new RefreshResult.Reused(Guid.NewGuid()));
        deps.TokenService.GetUserId("eyJ.access").Returns("u1");
        deps.UserService.FindByIdAsync("u1").Returns(new User { Id = "u1", Email = null });

        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.EmailService.DidNotReceive().SendEmailAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task Refresh_ReusedAndEmailSendThrows_StillReturns401()
    {
        // Email failure must not block returning 401 — would cascade transient SMTP outage into endpoint failures.
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

        var result = await controller.RefreshTokenAsync(new RefreshTokenDto { RefreshToken = "rt" });

        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    // ─── Logout (per-device) ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Logout_MissingSidClaim_Returns401()
    {
        // sid is the family ID — without it we can't revoke just one device's family.
        var (controller, _) = BuildController(sub: "u1", sid: null);

        var result = await controller.LogoutAsync();

        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task Logout_HappyPath_RevokesFamilyAndAccessToken()
    {
        var familyId = Guid.NewGuid();
        var (controller, deps) = BuildController(sub: "u1", sid: familyId.ToString());
        SetAuthorizationHeader(controller, "eyJ.access");

        var result = await controller.LogoutAsync();

        result.Should().BeOfType<OkObjectResult>();
        await deps.TokenService.Received(1).RevokeFamilyAsync(familyId, RevocationReasons.Logout);
        await deps.TokenService.Received(1).RevokeTokenAsync("eyJ.access", Arg.Any<string>(), RevocationReasons.Logout);
    }

    // ─── Logout (all devices) ───────────────────────────────────────────────────────────

    [Fact]
    public async Task LogoutAll_MissingSubClaim_Returns401()
    {
        var (controller, _) = BuildController(sub: null, sid: Guid.NewGuid().ToString());

        var result = await controller.LogoutAllAsync();

        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task LogoutAll_OrphanToken_RevokesOrphanAndReturnsOkIdempotent()
    {
        // sub points to deleted user — still revoke the presented token but return Ok so clients can retry safely.
        var (controller, deps) = BuildController(sub: "deleted-user", sid: Guid.NewGuid().ToString());
        SetAuthorizationHeader(controller, "eyJ.access");
        deps.UserService.FindByIdAsync("deleted-user").Returns((User?)null);

        var result = await controller.LogoutAllAsync();

        result.Should().BeOfType<OkObjectResult>();
        await deps.TokenService.Received(1).RevokeOrphanedTokenAsync("eyJ.access", Arg.Any<string>());
        await deps.UserService.DidNotReceive().InvalidateUserTokensAsync(
            Arg.Any<User>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task LogoutAll_HappyPath_InvalidatesEverythingAndRevokesAccessToken()
    {
        var (controller, deps) = BuildController(sub: "u1", sid: Guid.NewGuid().ToString());
        var user = new User { Id = "u1" };
        deps.UserService.FindByIdAsync("u1").Returns(user);
        SetAuthorizationHeader(controller, "eyJ.access");

        var result = await controller.LogoutAllAsync();

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
            NullLogger<AuthenticationController>.Instance,
            TestMetricsFactory.Create());

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
