using System.ComponentModel.DataAnnotations;
using AwesomeAssertions;

namespace AuthenticationService.TokenValidationLib.Tests;

/// <summary>
/// Pins the DataAnnotations contract on AuthenticationServiceOptions — consumed at
/// startup via AddOptions&lt;T&gt;.ValidateDataAnnotations() so a loosened [Required] would
/// let a misconfigured consumer boot silently. Also pins the HTTPS-by-default behaviour.
/// </summary>
public class AuthenticationServiceOptionsTests
{
    [Fact]
    public void RequireHttpsMetadata_DefaultsToTrue()
    {
        // arrange
        var options = new AuthenticationServiceOptions
        {
            Authority = "https://auth.example.com",
            Audience = "platform-api",
            Issuer = "https://auth.example.com",
        };

        // assert — HTTPS-by-default; weakening must be explicit operator opt-in.
        options.RequireHttpsMetadata.Should().BeTrue();
    }

    [Fact]
    public void Validate_AllRequiredFieldsPresent_PassesValidation()
    {
        // arrange
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
        // arrange
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

        // assert
        results.Should().Contain(r => r.MemberNames.Contains(missingProperty));
    }

    private static List<ValidationResult> ValidateRecursive(object instance)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(instance, new ValidationContext(instance), results, validateAllProperties: true);
        return results;
    }
}
