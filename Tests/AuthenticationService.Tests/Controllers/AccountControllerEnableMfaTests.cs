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
using AuthenticationService.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// Covers <c>GET /api/Account/enablemfa</c> — orphan-token guard, key generation,
/// provider validation, Email / Phone / Authenticator paths and Phone-path rollback on failure.
/// </summary>
public class AccountControllerEnableMfaTests
{
    [Fact]
    public async Task EnableMfa_OrphanToken_RevokesAndReturns401()
    {
        // sub claim resolved via TokenService.GetUserId — that user no longer exists.
        var (controller, deps) = BuildController();
        deps.TokenService.GetUserId(Arg.Any<string>()).Returns("ghost-user");
        deps.UserService.FindByIdAsync("ghost-user").Returns((User?)null);
        SetAuthorizationHeader(controller, "eyJ.access");

        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Email });

        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.TokenService.Received(1).RevokeOrphanedTokenAsync("eyJ.access", Arg.Any<string>());
    }

    [Fact]
    public async Task EnableMfa_NoAuthenticatorKeyOnFile_ResetsToGenerateOne()
    {
        // First-time enrolment: GetAuthenticatorKey returns null then key after reset. Skipping reset would serve a null key in the QR.
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user)
            .Returns((string?)null, "JBSWY3DPEHPK3PXP");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });

        await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Email });

        await deps.UserService.Received(1).ResetAuthenticatorKeyAsync(user);
    }

    [Fact]
    public async Task EnableMfa_ExistingKey_DoesNotResetIt()
    {
        // Re-enrolment must not invalidate an already-paired authenticator app.
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("EXISTING-KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });

        await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Email });

        await deps.UserService.DidNotReceive().ResetAuthenticatorKeyAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task EnableMfa_RequestedProviderNotInValidSet_Returns401()
    {
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });

        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Authenticator });

        var unauthorized = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorized.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.InvalidMfaProvider);
        await deps.UserService.DidNotReceive().SetMfaEnabledAsync(Arg.Any<User>(), Arg.Any<bool>());
    }

    [Fact]
    public async Task EnableMfa_EmailProvider_ReturnsResponseWithEmailProvider()
    {
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });

        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Email });

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
        // Must roll back the SetMfaEnabled it already called — otherwise user is left with MFA on but no working provider.
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Phone" });
        deps.UserService.GetMfaEnabledAsync(user).Returns(false);
        deps.SmsService.IsConfigured.Returns(false);

        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Phone });

        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.PhoneMfaNotConfigured);

        Received.InOrder(() =>
        {
            deps.UserService.SetMfaEnabledAsync(user, true);
            deps.UserService.SetMfaEnabledAsync(user, false);
        });
    }

    [Fact]
    public async Task EnableMfa_PhoneProviderButPhoneUnconfirmed_RollsBackMfaAnd400()
    {
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        user.PhoneNumber = "+44 1234 567890";
        user.PhoneNumberConfirmed = false;
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Phone" });
        deps.UserService.GetMfaEnabledAsync(user).Returns(false);
        deps.SmsService.IsConfigured.Returns(true);

        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Phone });

        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.PhoneNumberNotConfirmed);
        await deps.UserService.Received(1).SetMfaEnabledAsync(user, false);
    }

    [Fact]
    public async Task EnableMfa_PhoneProviderHappy_ReturnsResponseWithPhone()
    {
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        user.PhoneNumber = "+44 1234 567890";
        user.PhoneNumberConfirmed = true;
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Phone" });
        deps.SmsService.IsConfigured.Returns(true);

        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Phone });

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = ok.Value.Should().BeOfType<EnableMfaResponse>().Subject;
        response.EnabledMfaProvider.Should().Be(MfaProviders.Phone);
    }

    [Fact]
    public async Task EnableMfa_AuthenticatorProvider_ReturnsResponseWithQrCodeAndKey()
    {
        // Response must carry BOTH the QR PNG and the raw base32 key (in case scanning fails).
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("JBSWY3DPEHPK3PXP");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Authenticator" });

        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = MfaProviders.Authenticator });

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
        // Null DTO provider: controller leaves user.PreferredMfaProvider alone and uses the existing value.
        // The valid-providers list is set to string.Empty (which is what null MfaProviders.ToString() returns) so the membership check passes.
        var (controller, deps) = BuildController();
        var user = SeedUser(deps);
        user.PreferredMfaProvider = MfaProviders.Email;
        deps.UserService.GetAuthenticatorKeyAsync(user).Returns("KEY");
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { string.Empty });

        var result = await controller.EnableMfaAsync(new EnableMfaRequest { PreferredMfaProvider = null });

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
        // Controller pulls userId via TokenService.GetUserId — default so tests that don't override still resolve.
        deps.TokenService.GetUserId(Arg.Any<string>()).Returns("user-id-1");

        var controller = new AccountController(
            deps.EmailService, deps.SmsService, deps.TokenService, deps.UserService,
            Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" }),
            NullLogger<AccountController>.Instance,
            TestMetricsFactory.Create());

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
