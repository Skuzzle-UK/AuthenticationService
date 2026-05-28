using AuthenticationService.Constants;
using AuthenticationService.Settings;
using AuthenticationService.Validators;
using AwesomeAssertions;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Tests.Validators;

/// <summary>
/// Rejects startup if DatabaseSettings.Provider isn't in the wired-provider set —
/// catches typos and Phase-ahead-of-implementation misconfig (setting
/// Provider="PostgreSQL" before Phase 3 ships).
/// </summary>
public class DatabaseSettingsValidatorTests
{
    [Fact]
    public void NamedInstance_SkipsValidation()
    {
        // arrange
        var validator = new DatabaseSettingsValidator();
        var settings = new DatabaseSettings { Provider = "anything" };

        // act
        var result = validator.Validate(name: "namedInstance", settings);

        // assert
        result.Skipped.Should().BeTrue();
    }

    [Theory]
    [InlineData(DatabaseProviders.MySql)]
    [InlineData(DatabaseProviders.SqlServer)]
    [InlineData(DatabaseProviders.PostgreSQL)]
    public void SupportedProvider_Succeeds(string provider)
    {
        // arrange — all three providers in the multi-provider plan are now wired.
        var validator = new DatabaseSettingsValidator();
        var settings = new DatabaseSettings { Provider = provider };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankProvider_Fails(string? provider)
    {
        // arrange
        var validator = new DatabaseSettingsValidator();
        var settings = new DatabaseSettings { Provider = provider! };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("must be set");
    }

    [Theory]
    [InlineData("mssql")]
    [InlineData("Mongo")]
    [InlineData("mysql")] // case-sensitive — only the canonical name is accepted
    public void UnknownProvider_Fails(string provider)
    {
        // arrange — catches typos AND Phase-ahead-of-implementation misconfig.
        var validator = new DatabaseSettingsValidator();
        var settings = new DatabaseSettings { Provider = provider };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should()
            .Contain(provider, because: "the operator needs to see exactly what they typed.")
            .And.Contain("not supported")
            .And.Contain(DatabaseProviders.MySql, because: "the allowed-set must be visible in the error.");
    }

}
