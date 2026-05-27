using AuthenticationService.Settings;
using AuthenticationService.Tests.Helpers;
using AuthenticationService.Validators;
using AwesomeAssertions;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Tests.Validators;

/// <summary>
/// Rejects startup outside Development if the seed-admin password is the well-known
/// dev default — catches operators copying appsettings.Development.json without
/// overriding the password.
/// </summary>
public class AdminAccountSeedSettingsValidatorTests
{
    [Fact]
    public void NamedInstance_SkipsValidation()
    {
        // arrange — only acts on the default-named options instance so future named-options consumers can opt out.
        var environment = ValidatorTestHelpers.StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: "namedInstance", settings);

        // assert
        result.Skipped.Should().BeTrue();
    }

    [Fact]
    public void DevelopmentEnvironment_AllowsDevDefault()
    {
        // arrange
        var environment = ValidatorTestHelpers.StubEnvironment("Development");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void NonDevelopmentWithDevDefaultPassword_FailsWithExplicitMessage()
    {
        // arrange — catches the realistic deploy mistake: copy appsettings.Development.json into prod without overriding the password.
        var environment = ValidatorTestHelpers.StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("development default")
            .And.Contain("AdminAccountSeedSettings__Password",
                because: "operators read the failure message and must see the exact env-var name to fix the issue.");
    }

    [Fact]
    public void NonDevelopmentWithCustomPassword_Succeeds()
    {
        // arrange
        var environment = ValidatorTestHelpers.StubEnvironment("Production");
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pr0d!Pa$$w0rd1234",
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("QA")]
    [InlineData("CustomEnv")]
    public void AnyNonDevelopmentEnvironment_AppliesRule(string envName)
    {
        // arrange — only literal "Development" gets the bypass, every other env triggers the dev-default check.
        var environment = ValidatorTestHelpers.StubEnvironment(envName);
        var validator = new AdminAccountSeedSettingsValidator(environment);
        var settings = new AdminAccountSeedSettings
        {
            Email = "a@b.com",
            Password = "Pa5$word123-dev",
            FirstName = "A",
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
    }
}
