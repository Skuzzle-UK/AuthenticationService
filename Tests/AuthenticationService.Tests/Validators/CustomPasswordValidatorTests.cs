using AuthenticationService.Entities;
using AuthenticationService.Tests.Helpers;
using AuthenticationService.Validators;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Validators;

/// <summary>
/// Identity password validator that adds two rules on top of the framework defaults:
/// password must not equal the username or the email (case-insensitive).
/// </summary>
public class CustomPasswordValidatorTests
{
    [Fact]
    public async Task PasswordMatchesUsername_ReturnsSameUserPassError()
    {
        // arrange
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = ValidatorTestHelpers.StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        // act
        var result = await validator.ValidateAsync(manager, user, "alice");

        // assert
        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e =>
            e.Code == "SameUserPass" && e.Description.Contains("Username and Password can not be the same"));
    }

    [Fact]
    public async Task PasswordMatchesUsernameCaseInsensitive_StillFails()
    {
        // arrange
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = ValidatorTestHelpers.StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        // act
        var result = await validator.ValidateAsync(manager, user, "ALICE");

        // assert
        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e => e.Code == "SameUserPass");
    }

    [Fact]
    public async Task PasswordMatchesEmail_ReturnsSameEmailPassError()
    {
        // arrange
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = ValidatorTestHelpers.StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        // act
        var result = await validator.ValidateAsync(manager, user, "alice@example.com");

        // assert
        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e =>
            e.Code == "SameEmailPass" && e.Description.Contains("Email and Password can not be the same"));
    }

    [Fact]
    public async Task PasswordDifferentFromUsernameAndEmail_Succeeds()
    {
        // arrange
        var user = new User { UserName = "alice", Email = "alice@example.com" };
        var manager = ValidatorTestHelpers.StubUserManager(userName: "alice", email: "alice@example.com");
        var validator = new CustomPasswordValidator<User>();

        // act
        var result = await validator.ValidateAsync(manager, user, "Sup3rSecur3!");

        // assert
        result.Succeeded.Should().BeTrue();
    }
}
