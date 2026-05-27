using AuthenticationService.Entities;
using AuthenticationService.Tests.Helpers;
using AuthenticationService.Validators;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Validators;

/// <summary>
/// Identity user validator that rejects usernames in the configured deny-list. Tests
/// pin case-insensitivity, whitespace-tolerance, and the empty-deny-list fast path.
/// </summary>
public class ReservedUserNameValidatorTests
{
    [Fact]
    public async Task ReservedName_FailsWithReservedUserNameError()
    {
        // arrange
        var settings = ValidatorTestHelpers.MakeIdentitySettings(["administrator", "root", "support"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "administrator" };

        // act
        var result = await validator.ValidateAsync(ValidatorTestHelpers.StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle(e =>
            e.Code == "ReservedUserName"
            && e.Description.Contains("reserved"));
    }

    [Fact]
    public async Task ReservedNameDifferentCasing_StillFails()
    {
        // arrange — HashSet is OrdinalIgnoreCase so attacker can't bypass the deny-list by changing case.
        var settings = ValidatorTestHelpers.MakeIdentitySettings(["administrator"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "Administrator" };

        // act
        var result = await validator.ValidateAsync(ValidatorTestHelpers.StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task ReservedNameWithSurroundingWhitespace_StillFails()
    {
        // arrange — validator trims defensively in case AllowedUserNameCharacters admits leading whitespace.
        var settings = ValidatorTestHelpers.MakeIdentitySettings(["root"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "  root  " };

        // act
        var result = await validator.ValidateAsync(ValidatorTestHelpers.StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task NonReservedName_Succeeds()
    {
        // arrange
        var settings = ValidatorTestHelpers.MakeIdentitySettings(["administrator", "root"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "alice" };

        // act
        var result = await validator.ValidateAsync(ValidatorTestHelpers.StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task NullOrWhitespaceUserName_TreatedAsNotReserved()
    {
        // arrange — missing username isn't this validator's concern, Identity's own rules produce a more useful error.
        var settings = ValidatorTestHelpers.MakeIdentitySettings(["root"]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = null };

        // act
        var result = await validator.ValidateAsync(ValidatorTestHelpers.StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task EmptyDenyList_NeverFails()
    {
        // arrange
        var settings = ValidatorTestHelpers.MakeIdentitySettings([]);
        var validator = new ReservedUserNameValidator(settings);
        var user = new User { UserName = "administrator" };

        // act
        var result = await validator.ValidateAsync(ValidatorTestHelpers.StubUserManager(), user);

        // assert
        result.Succeeded.Should().BeTrue();
    }
}
