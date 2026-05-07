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
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// <para><c>GET /api/Account/enablemfa</c> turns MFA on for the current user. Has the
/// most branches of any AccountController endpoint:</para>
/// <list type="bullet">
///   <item><description>Orphan-token (sub matches no user) → revoke + 401.</description></item>
///   <item><description>No authenticator key on file → reset (generates one) before continuing.</description></item>
///   <item><description>Existing authenticator key → reuse, don't regenerate.</description></item>
///   <item><description>Requested provider not in the user's valid list → 401.</description></item>
///   <item><description><b>Email path</b> → <see cref="EnableMfaResponse"/> with provider only.</description></item>
///   <item><description><b>Phone path</b> + SMS not configured → rollback MFA + 400.</description></item>
///   <item><description><b>Phone path</b> + phone unconfirmed → rollback MFA + 400.</description></item>
///   <item><description><b>Phone path</b> happy → response with provider.</description></item>
///   <item><description><b>Authenticator path</b> → response with QR code + key.</description></item>
/// </list>
/// </summary>
public class AccountControllerEnableMfaTests
{
    [Fact]
    public async Task EnableMfa_OrphanToken_RevokesAndReturns401()
    {
        // arrange — sub claim resolved (via tokenService.GetUserId) but FindByIdAsync
        // returns null. EnableMfa uses GetUserId(token), not the principal's claim.
        var (controller, deps) = BuildController();
        deps.TokenService.GetUserId(Arg.Any<string>()).Returns("ghost-user");
        deps.UserService.FindByIdAsync("ghost-user").Returns((User?)null);
        SetAuthorizationHeader(controller, "eyJ.access");

        // act
        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Email });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.TokenService.Received(1).RevokeOrphanedTokenAsync("eyJ.access", Arg.Any<string>());
    }

    [Fact]
    public async Task EnableMfa_NoAuthenticatorKeyOnFile_ResetsToGenerateOne()
    {
        // arrange — first-time enrolment for this user. GetAuthenticatorKey returns null,
        // so the controller calls ResetAuthenticatorKeyAsync to generate one, then reads
        // it back. Pinned because skipping the reset would mean Authenticator-path
        // enrolment serves a null key in the QR (broken QR code).
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user)
            .Returns((string?)null, "JBSWY3DPEHPK3PXP"); // null first call, key after reset
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });

        // act
        await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Email });

        // assert
        await deps.UserService.Received(1).ResetAuthenticatorKeyAsync(user);
    }

    [Fact]
    public async Task EnableMfa_ExistingKey_DoesNotResetIt()
    {
        // arrange — re-enrolment / provider switch. Key already exists; reset would
        // invalidate every authenticator app the user already paired.
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("EXISTING-KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });

        // act
        await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Email });

        // assert
        await deps.UserService.DidNotReceive().ResetAuthenticatorKeyAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task EnableMfa_RequestedProviderNotInValidSet_Returns401()
    {
        // arrange — user asks for Authenticator but their valid-providers list is just
        // Email (e.g., the deployment hasn't enabled Authenticator).
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });

        // act
        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Authenticator });

        // assert
        var unauthorized = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorized.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.InvalidMfaProvider);
        // SetMfaEnabled NOT called because we rejected before that step.
        await deps.UserService.DidNotReceive().SetMfaEnabledAsync(Arg.Any<User>(), Arg.Any<bool>());
    }

    [Fact]
    public async Task EnableMfa_EmailProvider_ReturnsResponseWithEmailProvider()
    {
        // arrange — happy Email path.
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });

        // act
        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Email });

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = ok.Value.Should().BeOfType<EnableMfaResponse>().Subject;
        response.EnabledMfaProvider.Should().Be(MfaProviders.Email);
        response.QrCode.Should().BeNull();
        await deps.UserService.Received(1).SetMfaEnabledAsync(user, true);
        user.PreferredMfaProvider.Should().Be(MfaProviders.Email);
    }

    [Fact]
    public async Task EnableMfa_PhoneProviderButSmsNotConfigured_RollsBackMfaAnd400()
    {
        // arrange — user picks Phone but the deployment has no SMS provider. Controller
        // must roll back the SetMfaEnabled it already called (otherwise the user is left
        // with MFA enabled but no working provider, which would lock them out next login).
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Phone" });
        deps.UserService.GetMfaEnabledAsync(user).Returns(false); // pre-existing state
        deps.SmsService.IsConfigured.Returns(false);

        // act
        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Phone });

        // assert
        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.PhoneMfaNotConfigured);

        // SetMfaEnabled was called twice: once to enable (true), once to roll back (the
        // pre-existing value, false in this case).
        Received.InOrder(() =>
        {
            deps.UserService.SetMfaEnabledAsync(user, true);
            deps.UserService.SetMfaEnabledAsync(user, false);
        });
    }

    [Fact]
    public async Task EnableMfa_PhoneProviderButPhoneUnconfirmed_RollsBackMfaAnd400()
    {
        // arrange — SMS is configured but the user's phone isn't confirmed.
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        user.PhoneNumber = "+44 1234 567890";
        user.PhoneNumberConfirmed = false;
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Phone" });
        deps.UserService.GetMfaEnabledAsync(user).Returns(false);
        deps.SmsService.IsConfigured.Returns(true);

        // act
        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Phone });

        // assert
        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.PhoneNumberNotConfirmed);
        // Rollback to the pre-existing MFA state.
        await deps.UserService.Received(1).SetMfaEnabledAsync(user, false);
    }

    [Fact]
    public async Task EnableMfa_PhoneProviderHappy_ReturnsResponseWithPhone()
    {
        // arrange — SMS configured + phone confirmed.
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        user.PhoneNumber = "+44 1234 567890";
        user.PhoneNumberConfirmed = true;
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Phone" });
        deps.SmsService.IsConfigured.Returns(true);

        // act
        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Phone });

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = ok.Value.Should().BeOfType<EnableMfaResponse>().Subject;
        response.EnabledMfaProvider.Should().Be(MfaProviders.Phone);
    }

    [Fact]
    public async Task EnableMfa_AuthenticatorProvider_ReturnsResponseWithQrCodeAndKey()
    {
        // arrange — happy Authenticator path. Response must carry the QR PNG (so the user
        // can scan it) AND the raw base32 key (so they can manually type it if scanning fails).
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("JBSWY3DPEHPK3PXP");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Authenticator" });

        // act
        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Authenticator });

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = ok.Value.Should().BeOfType<EnableMfaResponse>().Subject;
        response.EnabledMfaProvider.Should().Be(MfaProviders.Authenticator);
        response.Key.Should().Be("JBSWY3DPEHPK3PXP");
        response.QrCode.Should().NotBeNull().And.NotBeEmpty(
            because: "Authenticator response carries the QR PNG bytes the user scans into their app.");
    }

    [Fact]
    public async Task EnableMfa_DtoProviderNull_DoesNotOverrideExistingPreferredProvider()
    {
        // arrange — DTO didn't pick a provider. Controller doesn't write to
        // user.PreferredMfaProvider in that case; the switch executes against whatever
        // value was already on the user (default Email, or a previously-saved choice).
        // The provider-membership check passes because the user's list of valid providers
        // includes whatever the controller serializes ToString() to (the test sets that
        // up explicitly so we exercise the "no DTO provider" branch).
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        user.PreferredMfaProvider = MfaProviders.Email;
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        // Nullable<MfaProviders>.ToString() on a null value returns string.Empty.
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { string.Empty });

        // act
        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = null });

        // assert — endpoint succeeded with the user's existing Email preference. The
        // user's PreferredMfaProvider must NOT have been overwritten — the conditional
        // assignment guards on `request.PreferredMfaProvider is not null`, so a null DTO
        // value leaves the field alone.
        result.Should().BeOfType<OkObjectResult>();
        user.PreferredMfaProvider.Should().Be(MfaProviders.Email);
        await deps.UserService.DidNotReceive().UpdateAsync(Arg.Any<User>());
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private static (AccountController controller, ControllerDeps deps) BuildController()
    {
        var deps = new ControllerDeps
        {
            EmailService = Substitute.For<IEmailService>(),
            SmsService = Substitute.For<ISmsService>(),
            TokenService = Substitute.For<ITokenService>(),
            UserService = Substitute.For<IUserService>(),
        };
        // The controller pulls userId via TokenService.GetUserId — provide a default so
        // tests that don't override it still resolve a user.
        deps.TokenService.GetUserId(Arg.Any<string>()).Returns("user-id-1");

        var controller = new AccountController(
            deps.EmailService, deps.SmsService, deps.TokenService, deps.UserService,
            Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" }),
            NullLogger<AccountController>.Instance);

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(
                    new[] { new Claim(ClaimConstants.Sub, "user-id-1") }, "test")),
            },
        };
        return (controller, deps);
    }

    private static User SeedUser(ControllerDeps deps, string id = "user-id-1")
    {
        var user = new User { Id = id, UserName = "alice", Email = "alice@example.com" };
        deps.UserService.FindByIdAsync(id).Returns(user);
        return user;
    }

    private static void SetAuthorizationHeader(AccountController controller, string token)
    {
        controller.ControllerContext.HttpContext.Request.Headers.Authorization
            = AuthSchemeConstants.BearerPrefix + token;
    }

    private sealed class ControllerDeps
    {
        public IEmailService EmailService { get; set; } = default!;
        public ISmsService SmsService { get; set; } = default!;
        public ITokenService TokenService { get; set; } = default!;
        public IUserService UserService { get; set; } = default!;
    }
}
