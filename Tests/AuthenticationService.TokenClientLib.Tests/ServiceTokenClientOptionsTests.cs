using System.ComponentModel.DataAnnotations;
using AwesomeAssertions;

namespace AuthenticationService.TokenClientLib.Tests;

/// <summary>
/// <para>The options class is consumed via <c>AddOptions&lt;T&gt;.ValidateDataAnnotations()</c>
/// at startup — meaning operator misconfiguration must be caught by the same
/// DataAnnotations pipeline the runtime uses. We verify the contract by running
/// validation directly:</para>
/// <list type="bullet">
///   <item><description>Every <c>[Required]</c>-marked field is actually rejected when missing — a regression here would let a service silently boot with no <c>ClientId</c> / <c>ClientSecret</c> / <c>Authority</c> and only discover it at the first outgoing call.</description></item>
///   <item><description>Defaults for <c>RequireHttpsMetadata</c>, <c>RefreshAtFractionOfLifetime</c>, and <c>MaxRetriesOnTransient</c> are stable — these are part of the security / behaviour contract consumers depend on without setting them explicitly.</description></item>
///   <item><description><c>RefreshAtFractionOfLifetime</c> <c>[Range]</c> bounds hold — a fraction outside [0.0, 1.0] would break the proactive-refresh maths and could either refresh constantly or never refresh.</description></item>
/// </list>
/// </summary>
public class ServiceTokenClientOptionsTests
{
    [Fact]
    public void Defaults_RequireHttpsMetadataIsTrue()
    {
        // arrange / act — fresh instance, no setters touched.
        var options = new ServiceTokenClientOptions();

        // assert — HTTPS-by-default is a security property; weakening it must be an explicit operator opt-in.
        options.RequireHttpsMetadata.Should().BeTrue();
    }

    [Fact]
    public void Defaults_RefreshAtFractionAndMaxRetriesMatchPlan()
    {
        // arrange / act
        var options = new ServiceTokenClientOptions();

        // assert — these defaults are part of the design contract (see service-token-client-plan.md).
        // 0.8 refresh fraction means we hit /oauth/token a single extra time per token-lifetime per
        // process. 3 retries means a transient backend wobble doesn't take down outgoing traffic.
        options.RefreshAtFractionOfLifetime.Should().Be(0.8);
        options.MaxRetriesOnTransient.Should().Be(3);
    }

    [Fact]
    public void Validate_AllRequiredFieldsPresent_PassesValidation()
    {
        // arrange — fully-populated options should be valid.
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
        // arrange — every [Required] field, individually nulled out, must trip validation.
        // If any stops being [Required] a misconfigured service starts up silently and
        // crashes on the first outgoing call — exactly what ValidateOnStart is meant to prevent.
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

        // assert — the error names the missing field so an operator sees what's actually wrong.
        results.Should().Contain(r => r.MemberNames.Contains(missingProperty));
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.5)]
    [InlineData(2.0)]
    public void Validate_RefreshAtFractionOutOfRange_FailsValidation(double fraction)
    {
        // arrange — out-of-range fraction would break the proactive-refresh maths.
        // Negative = refresh-time is past the token's birth; >1 = refresh-time is past expiry
        // (so proactive refresh never fires). Validator catches it early.
        var options = new ServiceTokenClientOptions
        {
            Authority = "https://auth.example.com",
            ClientId = "orders-service",
            ClientSecret = "super-secret",
            RefreshAtFractionOfLifetime = fraction,
        };

        // act
        var results = Validate(options);

        // assert — names the property so the operator's error message is actionable.
        results.Should().Contain(r => r.MemberNames.Contains(nameof(ServiceTokenClientOptions.RefreshAtFractionOfLifetime)));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(11)]
    public void Validate_MaxRetriesOutOfRange_FailsValidation(int retries)
    {
        // arrange — negative retries makes no sense; >10 is an upper sanity cap that prevents an
        // operator from accidentally configuring a multi-minute retry storm against /oauth/token.
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
