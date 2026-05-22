using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using AuthenticationService.Shared.Models;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Dtos.Response;

/// <summary>
/// Covers the two construction shapes of AuthenticationResponse — issued-token vs.
/// MFA-pending — and pins their mutually-exclusive field population (clients branch
/// on which fields are non-null).
/// </summary>
public class AuthenticationResponseTests
{
    [Fact]
    public void WithToken_ProducesTokenBearingResponse_NoMfaFields()
    {
        // arrange
        var token = new Token
        {
            Type = "Bearer",
            Value = "abc",
            Expires = DateTime.UtcNow.AddMinutes(15),
            RefreshToken = "ref",
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(14),
        };

        // act
        var response = AuthenticationResponse.WithToken(token);

        // assert — Token populated and MFA fields null; both populated would be a bug
        // (client uses Token!=null as "login completed" vs MfaRequired==true).
        response.Token.Should().BeSameAs(token);
        response.MfaRequired.Should().BeNull();
        response.MfaProvider.Should().BeNull();
        response.IsSuccessful.Should().BeTrue(because: "ApiResponse.IsSuccessful defaults true with no errors.");
    }

    [Fact]
    public void WithToken_NullToken_AllowedForCallSiteFlexibility()
    {
        // act
        var response = AuthenticationResponse.WithToken(null);

        // assert
        response.Token.Should().BeNull();
        response.MfaRequired.Should().BeNull();
        response.MfaProvider.Should().BeNull();
    }

    [Theory]
    [InlineData(MfaProviders.Email)]
    [InlineData(MfaProviders.Phone)]
    [InlineData(MfaProviders.Authenticator)]
    public void WithMfaRequired_AllProviders_ProducesMfaPendingShape(MfaProviders provider)
    {
        // act
        var response = AuthenticationResponse.WithMfaRequired(provider);

        // assert
        response.Token.Should().BeNull();
        response.MfaRequired.Should().BeTrue();
        response.MfaProvider.Should().Be(provider);
    }

    [Fact]
    public void WithMfaRequired_NullProvider_StillFlagsMfaButLeavesProviderNull()
    {
        // act
        var response = AuthenticationResponse.WithMfaRequired(null);

        // assert
        response.MfaRequired.Should().BeTrue();
        response.MfaProvider.Should().BeNull();
        response.Token.Should().BeNull();
    }

    [Fact]
    public void Inherits_ApiResponse_AddErrorFlipsToUnsuccessful()
    {
        // arrange — guards against a regression where factories break the inherited error pipeline.
        var response = AuthenticationResponse.WithMfaRequired(MfaProviders.Email);

        // act
        response.AddError("k", "v");

        // assert
        response.IsSuccessful.Should().BeFalse();
        response.Errors.Should().NotBeNull().And.HaveCount(1);
    }
}
