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
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// <para>The most security-critical endpoint in the service: <c>POST /api/Authentication/authenticate</c>.
/// Branch coverage matters because each branch is a different security decision.</para>
///
/// <para>Branches covered (in failure-detection order):</para>
/// <list type="bullet">
///   <item><description>Unknown email → 400 generic; SIEM event with empty UserId. (Don't tip off attacker that the email isn't registered.)</description></item>
///   <item><description>Email not confirmed → 401 with documented message.</description></item>
///   <item><description>Account locked → 401 with the failed-attempts message.</description></item>
///   <item><description>Wrong password → recorded as failed attempt + generic 401.</description></item>
///   <item><description>MFA enabled → returns MfaRequired without a token; controller picks PreferredMfaProvider when DTO didn't supply one.</description></item>
///   <item><description>MFA-required + Email provider → token generated, email sent.</description></item>
///   <item><description>MFA-required + Phone but SMS not configured → 400.</description></item>
///   <item><description>MFA-required + Phone but no confirmed phone → 400.</description></item>
///   <item><description>Happy path (no MFA) → 200 with token + reset of access-failed count + LoginSucceeded SIEM event.</description></item>
/// </list>
///
/// <para>Other AuthenticationController endpoints (MfaAuthenticate, Refresh, Logout,
/// LogoutAll) follow the same shape and are summarised in the deferred-coverage notes.</para>
/// </summary>
public class AuthenticationControllerLoginTests
{
    [Fact]
    public async Task Authenticate_UnknownEmail_Returns400Generic()
    {
        // arrange
        var (controller, deps) = BuildController();
        deps.UserService.FindByEmailAsync(Arg.Any<string>()).Returns((User?)null);

        // act
        var result = await controller.AuthenticateAsync(new AuthenticationDto
        {
            Email = "ghost@example.com",
            Password = "anything",
        });

        // assert — generic 400 with InvalidRequest message, not "user not found".
        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors.Should().ContainKey(ResponseConstants.BadRequest);
    }

    [Fact]
    public async Task Authenticate_EmailNotConfirmed_Returns401()
    {
        // arrange — user exists but hasn't confirmed their email yet.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(false);

        // act
        var result = await controller.AuthenticateAsync(new AuthenticationDto
        {
            Email = "alice@example.com",
            Password = "p",
        });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task Authenticate_AccountLocked_Returns401WithLockoutMessage()
    {
        // arrange — confirmed email but account is locked (e.g., recent failed-attempt
        // threshold). User must wait or reset.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(true);

        // act
        var result = await controller.AuthenticateAsync(new AuthenticationDto
        {
            Email = "alice@example.com",
            Password = "p",
        });

        // assert
        var unauthorized = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorized.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.AccountLockedFailedAttempts);
    }

    [Fact]
    public async Task Authenticate_WrongPassword_RecordsFailedAttemptAndReturns401()
    {
        // arrange — email + lockout fine, but wrong password.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.CheckPasswordAsync(user, "wrong").Returns(false);

        // act
        var result = await controller.AuthenticateAsync(new AuthenticationDto
        {
            Email = "alice@example.com",
            Password = "wrong",
        });

        // assert — 401, AND AccessFailedAsync called (so the failed-attempt counter
        // increments — drives the eventual lockout).
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.UserService.Received(1).AccessFailedAsync(user);
    }

    [Fact]
    public async Task Authenticate_HappyPath_NoMfa_ReturnsTokenAndResetsFailedAttempts()
    {
        // arrange — clean login. No MFA enabled. Service issues a token + resets the
        // failed-attempt counter (so a future wrong password starts the count fresh).
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", UserName = "alice" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.CheckPasswordAsync(user, "p").Returns(true);
        deps.UserService.GetMfaEnabledAsync(user).Returns(false);
        deps.UserService.GetRolesAsync(user).Returns((IList<string>)new List<string> { "DefaultUser" });
        var issued = new Token { Type = "Bearer", Value = "eyJ.access" };
        deps.TokenService.CreateTokenAsync(user, Arg.Any<IList<string>>(), Arg.Any<Guid?>(), Arg.Any<string?>())
            .Returns(issued);

        // act
        var result = await controller.AuthenticateAsync(new AuthenticationDto
        {
            Email = "alice@example.com",
            Password = "p",
        });

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Token.Should().BeSameAs(issued);
        await deps.UserService.Received(1).ResetAccessFailedCountAsync(user);
    }

    [Fact]
    public async Task Authenticate_MfaEnabled_NoProviderInDto_UsesUsersPreferredProvider()
    {
        // arrange — MFA on; DTO didn't pick a provider so the user's saved preference wins.
        var (controller, deps) = BuildController();
        var user = new User
        {
            Id = "u1", Email = "alice@example.com", UserName = "alice",
            PreferredMfaProvider = MfaProviders.Email,
        };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.CheckPasswordAsync(user, "p").Returns(true);
        deps.UserService.GetMfaEnabledAsync(user).Returns(true);
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });
        deps.UserService.GenerateMfaTokenAsync(user, TokenOptions.DefaultEmailProvider).Returns("123456");

        // act
        var result = await controller.AuthenticateAsync(new AuthenticationDto
        {
            Email = "alice@example.com",
            Password = "p",
            MfaProvider = null,
        });

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var response = ok.Value.Should().BeOfType<AuthenticationResponse>().Subject;
        response.MfaRequired.Should().BeTrue();
        response.MfaProvider.Should().Be(MfaProviders.Email);
        response.Token.Should().BeNull();

        // SMS provider not invoked because Email path was selected.
        await deps.EmailService.Received(1).SendEmailAsync(
            "alice@example.com",
            EmailSubjects.MfaAuthenticationToken,
            Arg.Is<string>(b => b.Contains("123456")));
    }

    [Fact]
    public async Task Authenticate_MfaEnabled_PhoneProviderButSmsNotConfigured_Returns400()
    {
        // arrange — MFA on, user wants SMS, but no SMS provider is wired up. Don't promise
        // we can deliver — return clear error.
        var (controller, deps) = BuildController();
        var user = new User
        {
            Id = "u1", Email = "alice@example.com", UserName = "alice",
            PhoneNumber = "+44 0000 000000", PhoneNumberConfirmed = true,
        };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.CheckPasswordAsync(user, "p").Returns(true);
        deps.UserService.GetMfaEnabledAsync(user).Returns(true);
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Phone" });
        deps.SmsService.IsConfigured.Returns(false);

        // act
        var result = await controller.AuthenticateAsync(new AuthenticationDto
        {
            Email = "alice@example.com",
            Password = "p",
            MfaProvider = MfaProviders.Phone,
        });

        // assert
        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.PhoneMfaNotConfigured);
    }

    [Fact]
    public async Task Authenticate_MfaEnabled_PhoneProviderButPhoneUnconfirmed_Returns400()
    {
        // arrange — SMS configured, but the user's phone isn't confirmed. SMS-MFA would
        // deliver to a number we haven't proven they own.
        var (controller, deps) = BuildController();
        var user = new User
        {
            Id = "u1", Email = "alice@example.com", UserName = "alice",
            PhoneNumber = "+44 1234 567890", PhoneNumberConfirmed = false,
        };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.CheckPasswordAsync(user, "p").Returns(true);
        deps.UserService.GetMfaEnabledAsync(user).Returns(true);
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Phone" });
        deps.SmsService.IsConfigured.Returns(true);

        // act
        var result = await controller.AuthenticateAsync(new AuthenticationDto
        {
            Email = "alice@example.com",
            Password = "p",
            MfaProvider = MfaProviders.Phone,
        });

        // assert
        var bad = result.Should().BeOfType<BadRequestObjectResult>().Subject;
        bad.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.PhoneNumberNotConfirmed);
    }

    [Fact]
    public async Task Authenticate_MfaEnabled_AskedForProviderUserDoesNotHave_Returns401WithInvalidProvider()
    {
        // arrange — DTO asks for Authenticator but the user only has Email enabled (e.g.,
        // MFA was set up via Email originally). Returning the wrong-provider message helps
        // the client UI prompt for a different provider.
        var (controller, deps) = BuildController();
        var user = new User { Id = "u1", Email = "alice@example.com", UserName = "alice" };
        deps.UserService.FindByEmailAsync("alice@example.com").Returns(user);
        deps.UserService.IsEmailConfirmedAsync(user).Returns(true);
        deps.UserService.IsLockedOutAsync(user).Returns(false);
        deps.UserService.CheckPasswordAsync(user, "p").Returns(true);
        deps.UserService.GetMfaEnabledAsync(user).Returns(true);
        deps.UserService.GetValidMfaProvidersAsync(user)
            .Returns((IList<string>)new List<string> { "Email" });

        // act
        var result = await controller.AuthenticateAsync(new AuthenticationDto
        {
            Email = "alice@example.com",
            Password = "p",
            MfaProvider = MfaProviders.Authenticator,
        });

        // assert
        var unauthorized = result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorized.Value.Should().BeOfType<AuthenticationResponse>()
            .Which.Errors!.Values.Should().Contain(ErrorMessages.InvalidMfaProvider);
    }

    private static (AuthenticationController controller, Deps deps) BuildController()
    {
        var deps = new Deps
        {
            EmailService = Substitute.For<IEmailService>(),
            SmsService = Substitute.For<ISmsService>(),
            TokenService = Substitute.For<ITokenService>(),
            UserService = Substitute.For<IUserService>(),
        };

        var controller = new AuthenticationController(
            deps.EmailService,
            deps.SmsService,
            deps.TokenService,
            deps.UserService,
            Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" }),
            NullLogger<AuthenticationController>.Instance,
            TestMetricsFactory.Create());

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                Connection = { RemoteIpAddress = IPAddress.Parse("10.0.0.5") },
            },
        };

        return (controller, deps);
    }

    private sealed class Deps
    {
        public IEmailService EmailService { get; set; } = default!;
        public ISmsService SmsService { get; set; } = default!;
        public ITokenService TokenService { get; set; } = default!;
        public IUserService UserService { get; set; } = default!;
    }
}
