using System.ComponentModel.DataAnnotations;
using AwesomeAssertions;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// Pins the DataAnnotations contract on ServiceTokenClientOptions — consumed at startup
/// via AddOptions&lt;T&gt;.ValidateDataAnnotations(), so a missing [Required] or loosened
/// [Range] would let a service boot misconfigured and only blow up at the first call.
/// </summary>
public class ServiceTokenClientOptionsTests
{
    [Fact]
    public void Defaults_RequireHttpsMetadataIsTrue()
    {
        // arrange
        var options = new ServiceTokenClientOptions();

        // assert — HTTPS-by-default is a security property; weakening must be explicit opt-in.
        options.RequireHttpsMetadata.Should().BeTrue();
    }

    [Fact]
    public void Defaults_RefreshAtFractionAndMaxRetriesMatchPlan()
    {
        // arrange
        var options = new ServiceTokenClientOptions();

        // assert — defaults are part of the design contract (service-token-client-plan.md).
        options.RefreshAtFractionOfLifetime.Should().Be(0.8);
        options.MaxRetriesOnTransient.Should().Be(3);
    }

    [Fact]
    public void Validate_AllRequiredFieldsPresent_PassesValidation()
    {
        // arrange
        var options = new ServiceTokenClientOptions
        {
            Authority = "https://auth.example.com",
            ClientId = "orders-service",
            ClientSecret = "super-secret",
        };

        // act
        var results = Validate(options);

        // assert
        results.Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(ServiceTokenClientOptions.Authority))]
    [InlineData(nameof(ServiceTokenClientOptions.ClientId))]
    [InlineData(nameof(ServiceTokenClientOptions.ClientSecret))]
    public void Validate_RequiredFieldMissing_FailsWithFieldNamed(string missingProperty)
    {
        // arrange
        var options = new ServiceTokenClientOptions
        {
            Authority = "https://auth.example.com",
            ClientId = "orders-service",
            ClientSecret = "super-secret",
        };
        switch (missingProperty)
        {
            case nameof(ServiceTokenClientOptions.Authority):
                options.Authority = null;
                break;
            case nameof(ServiceTokenClientOptions.ClientId):
                options.ClientId = null;
                break;
            case nameof(ServiceTokenClientOptions.ClientSecret):
                options.ClientSecret = null;
                break;
        }

        // act
        var results = Validate(options);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(missingProperty));
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.5)]
    [InlineData(2.0)]
    public void Validate_RefreshAtFractionOutOfRange_FailsValidation(double fraction)
    {
        // arrange — out-of-range fraction breaks the proactive-refresh maths (negative refreshes
        // constantly; >1 never refreshes).
        var options = new ServiceTokenClientOptions
        {
            Authority = "https://auth.example.com",
            ClientId = "orders-service",
            ClientSecret = "super-secret",
            RefreshAtFractionOfLifetime = fraction,
        };

        // act
        var results = Validate(options);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(ServiceTokenClientOptions.RefreshAtFractionOfLifetime)));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(11)]
    public void Validate_MaxRetriesOutOfRange_FailsValidation(int retries)
    {
        // arrange — upper sanity cap at 10; prevents an operator from configuring a multi-minute
        // retry storm against /oauth/token.
        var options = new ServiceTokenClientOptions
        {
            Authority = "https://auth.example.com",
            ClientId = "orders-service",
            ClientSecret = "super-secret",
            MaxRetriesOnTransient = retries,
        };

        // act
        var results = Validate(options);

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(nameof(ServiceTokenClientOptions.MaxRetriesOnTransient)));
    }

    private static List<ValidationResult> Validate(object instance)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(instance, new ValidationContext(instance), results, validateAllProperties: true);
        return results;
    }
}
