using AuthenticationService.Validators;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Validators;

/// <summary>
/// Validates the tenant-name rules from Decision 6 of the multi-tenancy plan: regex,
/// length, reserved-list, no consecutive hyphens, no pure-numeric.
/// </summary>
public class TenantNameValidatorTests
{
    private readonly TenantNameValidator _validator = new();

    [Theory]
    [InlineData("acme")]
    [InlineData("globex")]
    [InlineData("a-b")]
    [InlineData("contoso-uk")]
    [InlineData("user123")]
    [InlineData("123abc")]
    [InlineData("abc-1-def")]
    public void Valid_NamesReturnNull(string name)
    {
        // act + assert
        _validator.Validate(name).Should().BeNull(
            because: $"'{name}' satisfies all the tenant-name rules.");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Null_Empty_OrWhitespace_Fails(string? name)
    {
        // act + assert
        _validator.Validate(name).Should().NotBeNull(
            because: "the name is required to be a non-blank string.");
    }

    [Theory]
    [InlineData("ab")]      // too short (< 3)
    [InlineData("a")]
    public void TooShort_Fails(string name)
    {
        // act + assert
        _validator.Validate(name).Should().Contain("between",
            because: "the length-specific error message is friendlier than the regex one.");
    }

    [Fact]
    public void TooLong_Fails()
    {
        // arrange — 51 chars, over the 50-char cap.
        var name = new string('a', 51);

        // act + assert
        _validator.Validate(name).Should().Contain("between");
    }

    [Theory]
    [InlineData("-acme")]     // leading hyphen
    [InlineData("acme-")]     // trailing hyphen
    [InlineData("ACME")]      // uppercase
    [InlineData("acme corp")] // whitespace
    [InlineData("acme.corp")] // dot
    [InlineData("acme_corp")] // underscore
    public void InvalidFormat_Fails(string name)
    {
        // act + assert
        _validator.Validate(name).Should().NotBeNull(
            because: $"'{name}' violates the tenant-name format rules.");
    }

    [Theory]
    [InlineData("acme--corp")]
    [InlineData("a--b")]
    public void ConsecutiveHyphens_Fail(string name)
    {
        // act + assert
        _validator.Validate(name).Should().Contain("consecutive hyphens",
            because: "consecutive hyphens look wrong in URLs and we reject them explicitly.");
    }

    [Theory]
    [InlineData("123")]
    [InlineData("000")]
    [InlineData("12345")]
    public void PureNumeric_Fails(string name)
    {
        // act + assert
        _validator.Validate(name).Should().Contain("at least one letter",
            because: "pure-numeric names look like IDs in URLs and confuse readers.");
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("api")]
    [InlineData("login")]
    [InlineData("www")]
    [InlineData("oauth")]
    [InlineData("superadmin")]
    public void ReservedName_Fails(string name)
    {
        // act + assert
        _validator.Validate(name).Should().Contain("reserved",
            because: $"'{name}' is on the reserved deny-list to prevent URL collisions.");
    }

    [Fact]
    public void ReservedName_CaseInsensitive()
    {
        // arrange — attacker can't bypass the deny-list by changing case.
        // act + assert
        _validator.Validate("ADMIN").Should().NotBeNull(
            because: "the reserved check is case-insensitive.");
    }
}
