using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AwesomeAssertions;
using Microsoft.AspNetCore.Identity;
using NSubstitute;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// <para><see cref="UserService"/> is mostly a thin pass-through over
/// <see cref="UserManager{User}"/>. The only non-trivial method is
/// <see cref="UserService.InvalidateUserTokensAsync"/> which composes three operations
/// — security-stamp rotation, refresh-token family revoke, and (optionally) the
/// access-token deny-list write — into a single "log this user out everywhere"
/// operation. Tests focus there.</para>
///
/// <para>For the pass-through methods, a representative sample is verified to confirm
/// the delegation is wired correctly (rather than every single one — the cost/benefit
/// of one-line-per-method tests is poor and the compiler already catches signature
/// drift).</para>
/// </summary>
public class UserServiceTests
{
    // ─── InvalidateUserTokensAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task InvalidateUserTokensAsync_NoToken_RotatesStampAndRevokesRefreshFamilies()
    {
        // arrange — typical "logout all devices" flow: there's no specific access token
        // to deny-list (the user pressed a UI button, no inbound JWT to revoke).
        var (service, manager, tokens) = BuildService();
        var user = new User { Id = "u1" };

        // act
        await service.InvalidateUserTokensAsync(user, "10.0.0.1", RevocationReasons.LogoutAll, token: null);

        // assert — security-stamp rotation invalidates anything Identity caches for the
        // user; refresh-family revoke kills all in-flight sessions. The third call
        // (RevokeTokenAsync) is skipped because no token was supplied.
        await manager.Received(1).UpdateSecurityStampAsync(user);
        await tokens.Received(1).RevokeAllRefreshTokenFamiliesAsync(user.Id, RevocationReasons.LogoutAll);
        await tokens.DidNotReceive().RevokeTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task InvalidateUserTokensAsync_WithToken_AlsoRevokesAccessToken()
    {
        // arrange — "logout this device" flow: the user pressed a button while signed in,
        // so the inbound bearer token is present and we deny-list it explicitly so it
        // can't be replayed.
        var (service, manager, tokens) = BuildService();
        var user = new User { Id = "u1" };

        // act
        await service.InvalidateUserTokensAsync(user, "10.0.0.1", RevocationReasons.Logout, token: "eyJ.access");

        // assert — all three composing operations called.
        await manager.Received(1).UpdateSecurityStampAsync(user);
        await tokens.Received(1).RevokeAllRefreshTokenFamiliesAsync(user.Id, RevocationReasons.Logout);
        await tokens.Received(1).RevokeTokenAsync("eyJ.access", "10.0.0.1", RevocationReasons.Logout);
    }

    [Fact]
    public async Task InvalidateUserTokensAsync_EmptyTokenString_TreatedAsNoToken()
    {
        // arrange — defensive: "" should NOT be treated as a real token. Without this
        // guard the deny-list would be polluted with empty-jti rows and middleware
        // lookups would behave oddly for missing-Authorization-header requests.
        var (service, _, tokens) = BuildService();
        var user = new User { Id = "u1" };

        // act
        await service.InvalidateUserTokensAsync(user, "10.0.0.1", RevocationReasons.Logout, token: "");

        // assert
        await tokens.DidNotReceive().RevokeTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    // ─── Representative pass-throughs ───────────────────────────────────────────────────

    /// <summary>
    /// One representative test per "shape" of pass-through. Goal isn't 1:1 method coverage
    /// (the methods are one-liners — compiler catches drift) but to verify the wire-up
    /// pattern: each UserService method delegates to the matching UserManager call and
    /// returns its result.
    /// </summary>
    [Fact]
    public async Task FindByEmailAsync_DelegatesToUserManagerWithSameArg()
    {
        // arrange
        var (service, manager, _) = BuildService();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        manager.FindByEmailAsync("alice@example.com").Returns(user);

        // act
        var result = await service.FindByEmailAsync("alice@example.com");

        // assert
        result.Should().BeSameAs(user);
        await manager.Received(1).FindByEmailAsync("alice@example.com");
    }

    [Fact]
    public async Task GetMfaEnabledAsync_DelegatesToTwoFactorEnabledOnUserManager()
    {
        // arrange — the IUserService method is renamed (Mfa) but UserManager's underlying
        // method is still GetTwoFactorEnabledAsync. Verifies the rename didn't drift the
        // delegation target.
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.GetTwoFactorEnabledAsync(user).Returns(true);

        // act
        var enabled = await service.GetMfaEnabledAsync(user);

        // assert
        enabled.Should().BeTrue();
        await manager.Received(1).GetTwoFactorEnabledAsync(user);
    }

    [Fact]
    public async Task SetMfaEnabledAsync_DelegatesToSetTwoFactorEnabledOnUserManager()
    {
        // arrange
        var (service, manager, _) = BuildService();
        var user = new User();

        // act
        await service.SetMfaEnabledAsync(user, true);

        // assert
        await manager.Received(1).SetTwoFactorEnabledAsync(user, true);
    }

    [Fact]
    public async Task GenerateMfaTokenAsync_DelegatesToGenerateTwoFactorTokenOnUserManager()
    {
        // arrange
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.GenerateTwoFactorTokenAsync(user, "Email").Returns("123456");

        // act
        var token = await service.GenerateMfaTokenAsync(user, "Email");

        // assert
        token.Should().Be("123456");
        await manager.Received(1).GenerateTwoFactorTokenAsync(user, "Email");
    }

    [Fact]
    public async Task VerifyMfaTokenAsync_DelegatesToVerifyTwoFactorTokenOnUserManager()
    {
        // arrange
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.VerifyTwoFactorTokenAsync(user, "Email", "123456").Returns(true);

        // act
        var ok = await service.VerifyMfaTokenAsync(user, "Email", "123456");

        // assert
        ok.Should().BeTrue();
    }

    [Fact]
    public async Task GetValidMfaProvidersAsync_DelegatesAndReturnsList()
    {
        // arrange
        var (service, manager, _) = BuildService();
        var user = new User();
        IList<string> providers = new List<string> { "Email", "Phone" };
        manager.GetValidTwoFactorProvidersAsync(user).Returns(providers);

        // act
        var result = await service.GetValidMfaProvidersAsync(user);

        // assert
        result.Should().BeSameAs(providers);
    }

    [Fact]
    public async Task CreateAsync_DelegatesAndReturnsIdentityResult()
    {
        // arrange
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.CreateAsync(user, "p").Returns(IdentityResult.Success);

        // act
        var result = await service.CreateAsync(user, "p");

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task ResetPasswordAsync_DelegatesAndReturnsIdentityResult()
    {
        // arrange
        var (service, manager, _) = BuildService();
        var user = new User();
        var failure = IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "bad" });
        manager.ResetPasswordAsync(user, "tok", "newpw").Returns(failure);

        // act
        var result = await service.ResetPasswordAsync(user, "tok", "newpw");

        // assert
        result.Succeeded.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Code == "InvalidToken");
    }

    [Fact]
    public async Task IsLockedOutAsync_DelegatesToUserManager()
    {
        // arrange
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.IsLockedOutAsync(user).Returns(true);

        // act
        var locked = await service.IsLockedOutAsync(user);

        // assert
        locked.Should().BeTrue();
    }

    private static (UserService service, UserManager<User> manager, ITokenService tokens) BuildService()
    {
        var store = Substitute.For<IUserStore<User>>();
        var manager = Substitute.For<UserManager<User>>(store, null!, null!, null!, null!, null!, null!, null!, null!);
        manager.UpdateSecurityStampAsync(Arg.Any<User>()).Returns(IdentityResult.Success);
        var tokens = Substitute.For<ITokenService>();
        var service = new UserService(manager, tokens);
        return (service, manager, tokens);
    }
}
