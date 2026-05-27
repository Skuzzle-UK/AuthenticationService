using AuthenticationService.Settings;
using AuthenticationService.Tests.Helpers;
using AuthenticationService.Validators;
using AwesomeAssertions;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Tests.Validators;

/// <summary>
/// Rejects startup outside Development if DataProtectionSettings.Certificate.PfxPath is
/// missing — without the cert, the key ring sits in Redis as readable XML and anyone
/// with Redis read access can extract the keys and forge Identity tokens offline.
/// </summary>
public class DataProtectionSettingsValidatorTests
{
    [Fact]
    public void NamedInstance_SkipsValidation()
    {
        // arrange
        var validator = new DataProtectionSettingsValidator(ValidatorTestHelpers.StubEnvironment("Production"));
        var settings = new DataProtectionSettings();

        // act
        var result = validator.Validate(name: "namedInstance", settings);

        // assert
        result.Skipped.Should().BeTrue();
    }

    [Fact]
    public void Development_AllowsMissingCert()
    {
        // arrange — `dotnet run` first-time must not require a PFX file on disk.
        var validator = new DataProtectionSettingsValidator(ValidatorTestHelpers.StubEnvironment("Development"));
        var settings = new DataProtectionSettings();

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void NonDevelopmentCertMissing_FailsWithExplicitMessage()
    {
        // arrange — the silent-failure case: keys sit in Redis as readable XML, anyone with
        // Redis read access can extract them and forge Identity tokens offline.
        var validator = new DataProtectionSettingsValidator(ValidatorTestHelpers.StubEnvironment("Production"));
        var settings = new DataProtectionSettings { Certificate = null };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should()
            .Contain("PfxPath", because: "operators need the exact setting name to fix it.")
            .And.Contain("readable XML", because: "the consequence trips even non-security-minded operators.")
            .And.Contain("DataProtectionSettings__Certificate__PfxPath",
                because: "the env-var form is the most common how-to-fix path.");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void NonDevelopmentPfxPathBlank_Fails(string? pfxPath)
    {
        // arrange — null, empty, and whitespace all mean "not configured".
        var validator = new DataProtectionSettingsValidator(ValidatorTestHelpers.StubEnvironment("Production"));
        var settings = new DataProtectionSettings
        {
            Certificate = new DataProtectionCertificateSettings { PfxPath = pfxPath },
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
    }

    [Fact]
    public void NonDevelopmentPfxPathPopulated_Succeeds()
    {
        // arrange — a real path is enough. The validator doesn't check that the file exists;
        // that's the cert loader's job and the failure is loud enough on its own.
        var validator = new DataProtectionSettingsValidator(ValidatorTestHelpers.StubEnvironment("Production"));
        var settings = new DataProtectionSettings
        {
            Certificate = new DataProtectionCertificateSettings { PfxPath = "/run/secrets/data-protection.pfx" },
        };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("Production")]
    [InlineData("custom-env-name")]
    public void AnyNonDevelopmentEnv_RequiresCert(string envName)
    {
        // arrange
        var validator = new DataProtectionSettingsValidator(ValidatorTestHelpers.StubEnvironment(envName));
        var settings = new DataProtectionSettings();

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
    }
}
