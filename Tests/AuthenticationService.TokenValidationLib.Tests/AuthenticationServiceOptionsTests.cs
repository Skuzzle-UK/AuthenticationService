using System.ComponentModel.DataAnnotations;
using AwesomeAssertions;

namespace AuthenticationService.TokenValidationLib.Tests;

/// <summary>
/// <para>The options class is consumed via <c>AddOptions&lt;T&gt;.ValidateDataAnnotations()</c>
/// at startup — meaning operator misconfiguration must be caught by the same DataAnnotations
/// pipeline the runtime uses. These tests verify the contract by running validation directly:</para>
/// <list type="bullet">
///   <item><description>The <c>[Required]</c>-marked properties are actually rejected when missing — a regression here would let the service silently boot with no Authority / Audience / Issuer.</description></item>
///   <item><description>Default <c>RequireHttpsMetadata = true</c> — important because consumers who forget to set it must still get HTTPS-only by default. A change to the default would silently weaken security.</description></item>
/// </list>
/// </summary>
public class AuthenticationServiceOptionsTests
{
    [Fact]
    public void RequireHttpsMetadata_DefaultsToTrue()
    {
        // arrange
        // act
        var options = new AuthenticationServiceOptions
        {
            Authority = "https://auth.example.com",
            Audience = "platform-api",
            Issuer = "https://auth.example.com",
        };

        // assert — defaults to true so consumers who omit the setting still get HTTPS metadata.
        options.RequireHttpsMetadata.Should().BeTrue();
    }

    [Fact]
    public void Validate_AllRequiredFieldsPresent_PassesValidation()
    {
        // arrange — fully-populated options should be valid.
        var options = new AuthenticationServiceOptions
        {
            Authority = "https://auth.example.com",
            Audience = "platform-api",
            Issuer = "https://auth.example.com",
        };

        // act
        var results = ValidateRecursive(options);

        // assert
        results.Should().BeEmpty();
    }

    [Theory]
    [InlineData(nameof(AuthenticationServiceOptions.Authority))]
    [InlineData(nameof(AuthenticationServiceOptions.Audience))]
    [InlineData(nameof(AuthenticationServiceOptions.Issuer))]
    public void Validate_RequiredFieldNullOrEmpty_FailsWithFieldNamed(string missingProperty)
    {
        // arrange — every [Required] field, individually nulled out, must trip validation.
        // If any of these stops being [Required] the consumer service starts silently
        // misconfigured, which is exactly what ValidateOnStart() is meant to prevent.
        var options = new AuthenticationServiceOptions
        {
            Authority = "https://auth.example.com",
            Audience = "platform-api",
            Issuer = "https://auth.example.com",
        };

        switch (missingProperty)
        {
            case nameof(AuthenticationServiceOptions.Authority):
                options.Authority = null!;
                break;
            case nameof(AuthenticationServiceOptions.Audience):
                options.Audience = null!;
                break;
            case nameof(AuthenticationServiceOptions.Issuer):
                options.Issuer = null!;
                break;
        }

        // act
        var results = ValidateRecursive(options);

        // assert — the error must name the missing field so operators see exactly what's wrong.
        results.Should().Contain(r => r.MemberNames.Contains(missingProperty));
    }

    private static List<ValidationResult> ValidateRecursive(object instance)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(instance, new ValidationContext(instance), results, validateAllProperties: true);
        return results;
    }
}
