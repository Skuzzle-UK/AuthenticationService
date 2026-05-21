using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AwesomeAssertions;
using Microsoft.AspNetCore.Identity;
using NSubstitute;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// <see cref="UserService"/> is mostly pass-through over <see cref="UserManager{User}"/>;
/// <see cref="UserService.InvalidateUserTokensAsync"/> is the only composing method and gets focus.
/// </summary>
public class UserServiceTests
{
    // ─── InvalidateUserTokensAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task InvalidateUserTokensAsync_NoToken_RotatesStampAndRevokesRefreshFamilies()
    {
        // "Logout all devices" path: no inbound access token to deny-list.
        var (service, manager, tokens) = BuildService();
        var user = new User { Id = "u1" };

        await service.InvalidateUserTokensAsync(user, "10.0.0.1", RevocationReasons.LogoutAll, token: null);

        await manager.Received(1).UpdateSecurityStampAsync(user);
        await tokens.Received(1).RevokeAllRefreshTokenFamiliesAsync(user.Id, RevocationReasons.LogoutAll);
        await tokens.DidNotReceive().RevokeTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task InvalidateUserTokensAsync_WithToken_AlsoRevokesAccessToken()
    {
        // "Logout this device" path: inbound bearer is deny-listed explicitly so it can't be replayed.
        var (service, manager, tokens) = BuildService();
        var user = new User { Id = "u1" };

        await service.InvalidateUserTokensAsync(user, "10.0.0.1", RevocationReasons.Logout, token: "eyJ.access");

        await manager.Received(1).UpdateSecurityStampAsync(user);
        await tokens.Received(1).RevokeAllRefreshTokenFamiliesAsync(user.Id, RevocationReasons.Logout);
        await tokens.Received(1).RevokeTokenAsync("eyJ.access", "10.0.0.1", RevocationReasons.Logout);
    }

    [Fact]
    public async Task InvalidateUserTokensAsync_EmptyTokenString_TreatedAsNoToken()
    {
        // Defensive: "" must not be treated as a real token — would pollute deny-list with empty-jti rows.
        var (service, _, tokens) = BuildService();
        var user = new User { Id = "u1" };

        await service.InvalidateUserTokensAsync(user, "10.0.0.1", RevocationReasons.Logout, token: "");

        await tokens.DidNotReceive().RevokeTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    // ─── Representative pass-throughs ───────────────────────────────────────────────────

    [Fact]
    public async Task FindByEmailAsync_DelegatesToUserManagerWithSameArg()
    {
        var (service, manager, _) = BuildService();
        var user = new User { Id = "u1", Email = "alice@example.com" };
        manager.FindByEmailAsync("alice@example.com").Returns(user);

        var result = await service.FindByEmailAsync("alice@example.com");

        result.Should().BeSameAs(user);
        await manager.Received(1).FindByEmailAsync("alice@example.com");
    }

    [Fact]
    public async Task GetMfaEnabledAsync_DelegatesToTwoFactorEnabledOnUserManager()
    {
        // IUserService method is renamed (Mfa) but UserManager's underlying call is still GetTwoFactorEnabledAsync.
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.GetTwoFactorEnabledAsync(user).Returns(true);

        var enabled = await service.GetMfaEnabledAsync(user);

        enabled.Should().BeTrue();
        await manager.Received(1).GetTwoFactorEnabledAsync(user);
    }

    [Fact]
    public async Task SetMfaEnabledAsync_DelegatesToSetTwoFactorEnabledOnUserManager()
    {
        var (service, manager, _) = BuildService();
        var user = new User();

        await service.SetMfaEnabledAsync(user, true);

        await manager.Received(1).SetTwoFactorEnabledAsync(user, true);
    }

    [Fact]
    public async Task GenerateMfaTokenAsync_DelegatesToGenerateTwoFactorTokenOnUserManager()
    {
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.GenerateTwoFactorTokenAsync(user, "Email").Returns("123456");

        var token = await service.GenerateMfaTokenAsync(user, "Email");

        token.Should().Be("123456");
        await manager.Received(1).GenerateTwoFactorTokenAsync(user, "Email");
    }

    [Fact]
    public async Task VerifyMfaTokenAsync_DelegatesToVerifyTwoFactorTokenOnUserManager()
    {
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.VerifyTwoFactorTokenAsync(user, "Email", "123456").Returns(true);

        var ok = await service.VerifyMfaTokenAsync(user, "Email", "123456");

        ok.Should().BeTrue();
    }

    [Fact]
    public async Task GetValidMfaProvidersAsync_DelegatesAndReturnsList()
    {
        var (service, manager, _) = BuildService();
        var user = new User();
        IList<string> providers = new List<string> { "Email", "Phone" };
        manager.GetValidTwoFactorProvidersAsync(user).Returns(providers);

        var result = await service.GetValidMfaProvidersAsync(user);

        result.Should().BeSameAs(providers);
    }

    [Fact]
    public async Task CreateAsync_DelegatesAndReturnsIdentityResult()
    {
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.CreateAsync(user, "p").Returns(IdentityResult.Success);

        var result = await service.CreateAsync(user, "p");

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task ResetPasswordAsync_DelegatesAndReturnsIdentityResult()
    {
        var (service, manager, _) = BuildService();
        var user = new User();
        var failure = IdentityResult.Failed(new IdentityError { Code = "InvalidToken", Description = "bad" });
        manager.ResetPasswordAsync(user, "tok", "newpw").Returns(failure);

        var result = await service.ResetPasswordAsync(user, "tok", "newpw");

        result.Succeeded.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Code == "InvalidToken");
    }

    [Fact]
    public async Task IsLockedOutAsync_DelegatesToUserManager()
    {
        var (service, manager, _) = BuildService();
        var user = new User();
        manager.IsLockedOutAsync(user).Returns(true);

        var locked = await service.IsLockedOutAsync(user);

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
