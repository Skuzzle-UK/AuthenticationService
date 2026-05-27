using AuthenticationService.Settings;
using AuthenticationService.Tests.Helpers;
using AuthenticationService.Validators;
using AwesomeAssertions;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Tests.Validators;

/// <summary>
/// Rejects startup outside Development if both KnownNetworks and KnownProxies are empty —
/// behind a proxy that means X-Forwarded-For is ignored, audit logs record the LB IP,
/// and the rate limiter buckets the entire cluster's traffic under one IP.
/// </summary>
public class ForwardedHeadersSettingsValidatorTests
{
    [Fact]
    public void NamedInstance_SkipsValidation()
    {
        // arrange
        var validator = new ForwardedHeadersSettingsValidator(ValidatorTestHelpers.StubEnvironment("Production"));
        var settings = new ForwardedHeadersSettings();

        // act
        var result = validator.Validate(name: "namedInstance", settings);

        // assert
        result.Skipped.Should().BeTrue();
    }

    [Fact]
    public void Development_AllowsEmptyLists()
    {
        // arrange — local dev with no proxy in front is normal.
        var validator = new ForwardedHeadersSettingsValidator(ValidatorTestHelpers.StubEnvironment("Development"));
        var settings = new ForwardedHeadersSettings();

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void NonDevelopmentBothEmpty_FailsWithExplicitMessage()
    {
        // arrange — the silent-failure case: deployed behind a proxy, lists empty,
        // X-Forwarded-For ignored, audit logs and rate limiting both blind to client IP.
        var validator = new ForwardedHeadersSettingsValidator(ValidatorTestHelpers.StubEnvironment("Production"));
        var settings = new ForwardedHeadersSettings();

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should()
            .Contain("KnownNetworks", because: "operators need the exact setting name to fix it.")
            .And.Contain("KnownProxies")
            .And.Contain("rate-limit", because: "the consequence trips even non-security-minded operators.");
    }

    [Fact]
    public void NonDevelopmentKnownNetworksPopulated_Succeeds()
    {
        // arrange — a single CIDR is enough to make the middleware honour the header.
        var validator = new ForwardedHeadersSettingsValidator(ValidatorTestHelpers.StubEnvironment("Production"));
        var settings = new ForwardedHeadersSettings { KnownNetworks = { "10.0.0.0/8" } };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void NonDevelopmentKnownProxiesPopulated_Succeeds()
    {
        // arrange — KnownProxies alone is also a valid configuration.
        var validator = new ForwardedHeadersSettingsValidator(ValidatorTestHelpers.StubEnvironment("Production"));
        var settings = new ForwardedHeadersSettings { KnownProxies = { "203.0.113.10" } };

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Succeeded.Should().BeTrue();
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("Production")]
    [InlineData("custom-env-name")]
    public void AnyNonDevelopmentEnv_TreatsEmptyAsError(string envName)
    {
        // arrange
        var validator = new ForwardedHeadersSettingsValidator(ValidatorTestHelpers.StubEnvironment(envName));
        var settings = new ForwardedHeadersSettings();

        // act
        var result = validator.Validate(name: Options.DefaultName, settings);

        // assert
        result.Failed.Should().BeTrue();
    }
}
