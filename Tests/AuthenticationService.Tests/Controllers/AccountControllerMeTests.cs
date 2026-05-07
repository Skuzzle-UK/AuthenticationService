using System.Security.Claims;
using AuthenticationService.Constants;
using AuthenticationService.Controllers;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// <para>Covers the two profile endpoints on <see cref="AccountController"/>:</para>
/// <list type="bullet">
///   <item><description><b>GET /me</b> — happy, missing-sub-claim 401, orphan-token (sub matches no user) → revoke + 401.</description></item>
///   <item><description><b>PUT /me</b> — null body 400, missing-sub-claim 401, orphan-token revoke + 401, no-changes 200 with no DB write, partial-update writes only changed fields, phone-change resets PhoneNumberConfirmed.</description></item>
/// </list>
/// <para>The other AccountController endpoints (EnableMfa, ForgotPassword, ResetForgottenPassword,
/// ChangePassword, LockAccount) follow the same general shape — orphan token guard +
/// happy + a few defined failure modes — and are summarised in the deferred-coverage
/// section in the test project's README. Adding them follows the same pattern as the
/// tests below.</para>
/// </summary>
public class AccountControllerMeTests
{
    // ─── GET /me ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GET_Me_HappyPath_ReturnsMeResponseWithProfileSnapshot()
    {
        // arrange — authenticated request with sub claim resolving to a real user.
        var (controller, deps) = BuildController(subClaim: "user-id-1");
        var user = SeedUser(deps, id: "user-id-1");
        deps.UserService.GetRolesAsync(user).Returns((IList<string>)new List<string> { "DefaultUser" });
        deps.UserService.GetMfaEnabledAsync(user).Returns(false);

        // act
        var result = await controller.MeAsync();

        // assert
        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var body = ok.Value.Should().BeOfType<MeResponse>().Subject;
        body.Id.Should().Be(user.Id);
        body.UserName.Should().Be(user.UserName);
        body.Email.Should().Be(user.Email);
        body.Roles.Should().BeEquivalentTo(["DefaultUser"]);
    }

    [Fact]
    public async Task GET_Me_MissingSubClaim_Returns401()
    {
        // arrange — no sub claim on the principal (e.g., an unauthenticated request slipped
        // past the [Authorize] attribute somehow, or the JWT had no sub).
        var (controller, _) = BuildController(subClaim: null);

        // act
        var result = await controller.MeAsync();

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>()
            .Which.Value.Should().BeOfType<ApiResponse>()
            .Which.Errors.Should().ContainKey(ResponseConstants.Unauthorized);
    }

    [Fact]
    public async Task GET_Me_OrphanToken_RevokesTokenAndReturns401()
    {
        // arrange — sub claim points to a user that no longer exists. The controller
        // defensively revokes the token (so subsequent requests are rejected by middleware)
        // before returning 401.
        var (controller, deps) = BuildController(subClaim: "deleted-user");
        deps.UserService.FindByIdAsync("deleted-user").Returns((User?)null);
        SetAuthorizationHeader(controller, "eyJ.access");

        // act
        var result = await controller.MeAsync();

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.TokenService.Received(1).RevokeOrphanedTokenAsync("eyJ.access", Arg.Any<string>());
    }

    // ─── PUT /me ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PUT_Me_NullBody_Returns400()
    {
        // arrange
        var (controller, _) = BuildController(subClaim: "user-id-1");

        // act
        var result = await controller.UpdateProfileAsync(request: null!);

        // assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task PUT_Me_MissingSubClaim_Returns401()
    {
        // arrange
        var (controller, _) = BuildController(subClaim: null);

        // act
        var result = await controller.UpdateProfileAsync(new UpdateProfileDto());

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task PUT_Me_OrphanToken_RevokesAndReturns401()
    {
        // arrange — same orphan-token defence as GET /me.
        var (controller, deps) = BuildController(subClaim: "deleted-user");
        deps.UserService.FindByIdAsync("deleted-user").Returns((User?)null);
        SetAuthorizationHeader(controller, "eyJ.access");

        // act
        var result = await controller.UpdateProfileAsync(new UpdateProfileDto { FirstName = "A" });

        // assert
        result.Should().BeOfType<UnauthorizedObjectResult>();
        await deps.TokenService.Received(1).RevokeOrphanedTokenAsync("eyJ.access", Arg.Any<string>());
        // No update attempted on a non-existent user.
        await deps.UserService.DidNotReceive().UpdateAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task PUT_Me_NoActualChanges_ReturnsOkWithoutWritingToDatabase()
    {
        // arrange — DTO carries values that match the user's existing profile. Controller
        // detects "no fields differ" and returns 200 without calling UpdateAsync.
        var (controller, deps) = BuildController(subClaim: "user-id-1");
        var user = SeedUser(deps, id: "user-id-1");
        user.FirstName = "Alice";

        // act
        var result = await controller.UpdateProfileAsync(new UpdateProfileDto { FirstName = "Alice" });

        // assert
        result.Should().BeOfType<OkObjectResult>();
        await deps.UserService.DidNotReceive().UpdateAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task PUT_Me_PartialUpdate_OnlyAppliesNonNullChangedFields()
    {
        // arrange — user has FirstName + LastName set. DTO sends only FirstName change.
        // LastName must remain untouched.
        var (controller, deps) = BuildController(subClaim: "user-id-1");
        var user = SeedUser(deps, id: "user-id-1");
        user.FirstName = "Alice";
        user.LastName = "Smith";

        // act
        var result = await controller.UpdateProfileAsync(new UpdateProfileDto { FirstName = "Alicia" });

        // assert
        result.Should().BeOfType<OkObjectResult>();
        user.FirstName.Should().Be("Alicia");
        user.LastName.Should().Be("Smith", because: "LastName must not be touched when DTO leaves it null.");
        await deps.UserService.Received(1).UpdateAsync(user);
    }

    [Fact]
    public async Task PUT_Me_PhoneNumberChange_ResetsPhoneNumberConfirmed()
    {
        // arrange — phone confirmed. Changing the phone number must reset confirmation
        // (otherwise SMS-MFA would target the old number using the old confirmation).
        var (controller, deps) = BuildController(subClaim: "user-id-1");
        var user = SeedUser(deps, id: "user-id-1");
        user.PhoneNumber = "+44 1111 111111";
        user.PhoneNumberConfirmed = true;

        // act
        await controller.UpdateProfileAsync(new UpdateProfileDto { PhoneNumber = "+44 2222 222222" });

        // assert
        user.PhoneNumber.Should().Be("+44 2222 222222");
        user.PhoneNumberConfirmed.Should().BeFalse(
            because: "the phone number changed; the old confirmation no longer applies.");
        await deps.UserService.Received(1).UpdateAsync(user);
    }

    [Fact]
    public async Task PUT_Me_PhoneNumberSameValue_DoesNotResetConfirmed()
    {
        // arrange — DTO carries the same phone number. Controller short-circuits the
        // change-detection so PhoneNumberConfirmed isn't reset.
        var (controller, deps) = BuildController(subClaim: "user-id-1");
        var user = SeedUser(deps, id: "user-id-1");
        user.PhoneNumber = "+44 1111 111111";
        user.PhoneNumberConfirmed = true;

        // act
        await controller.UpdateProfileAsync(new UpdateProfileDto { PhoneNumber = "+44 1111 111111" });

        // assert
        user.PhoneNumberConfirmed.Should().BeTrue();
        await deps.UserService.DidNotReceive().UpdateAsync(Arg.Any<User>());
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    private static (AccountController controller, AccountControllerDeps deps) BuildController(string? subClaim)
    {
        var deps = new AccountControllerDeps
        {
            EmailService = Substitute.For<IEmailService>(),
            SmsService = Substitute.For<ISmsService>(),
            TokenService = Substitute.For<ITokenService>(),
            UserService = Substitute.For<IUserService>(),
        };

        var controller = new AccountController(
            deps.EmailService,
            deps.SmsService,
            deps.TokenService,
            deps.UserService,
            Options.Create(new PublicUrlSettings { BaseUrl = "https://auth.test" }),
            NullLogger<AccountController>.Instance);

        // Build a ClaimsPrincipal with (or without) the sub claim.
        var claims = new List<Claim>();
        if (subClaim is not null) claims.Add(new Claim(ClaimConstants.Sub, subClaim));
        var identity = new ClaimsIdentity(claims, authenticationType: "test");
        var principal = new ClaimsPrincipal(identity);

        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = principal },
        };

        return (controller, deps);
    }

    private static User SeedUser(AccountControllerDeps deps, string id)
    {
        var user = new User
        {
            Id = id,
            UserName = "alice",
            Email = "alice@example.com",
        };
        deps.UserService.FindByIdAsync(id).Returns(user);
        return user;
    }

    private static void SetAuthorizationHeader(AccountController controller, string token)
    {
        controller.ControllerContext.HttpContext.Request.Headers.Authorization
            = AuthSchemeConstants.BearerPrefix + token;
    }

    private sealed class AccountControllerDeps
    {
        public IEmailService EmailService { get; set; } = default!;
        public ISmsService SmsService { get; set; } = default!;
        public ITokenService TokenService { get; set; } = default!;
        public IUserService UserService { get; set; } = default!;
    }
}
