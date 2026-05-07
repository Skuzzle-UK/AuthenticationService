using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using AuthenticationService.Shared.Models;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Dtos.Response;

/// <summary>
/// <para><see cref="AuthenticationResponse"/> has two construction shapes — issued-token vs.
/// MFA-pending — created via static factories. The factories must produce mutually-exclusive
/// shapes (a token-bearing response with no MFA prompt vs. an MFA-pending response with no
/// token) because clients branch on which fields are populated. Tests verify each path:</para>
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

        // assert — token populated; MFA fields stay null because the client uses Token!=null
        // as "login completed" and MfaRequired==true as "needs MFA". Both true would be a bug.
        response.Token.Should().BeSameAs(token);
        response.MfaRequired.Should().BeNull();
        response.MfaProvider.Should().BeNull();
        response.IsSuccessful.Should().BeTrue(because: "ApiResponse.IsSuccessful defaults true with no errors.");
    }

    [Fact]
    public void WithToken_NullToken_AllowedForCallSiteFlexibility()
    {
        // arrange — the factory accepts a nullable Token (some callers pass straight from a
        // service that may legitimately return null and want the envelope unchanged).

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
        // arrange / act
        var response = AuthenticationResponse.WithMfaRequired(provider);

        // assert — MFA-pending shape: no token, MfaRequired=true, named provider so the
        // client knows which credential UI to show.
        response.Token.Should().BeNull();
        response.MfaRequired.Should().BeTrue();
        response.MfaProvider.Should().Be(provider);
    }

    [Fact]
    public void WithMfaRequired_NullProvider_StillFlagsMfaButLeavesProviderNull()
    {
        // arrange / act — defensive case for a server that determines MFA is needed but
        // hasn't yet picked a provider (shouldn't happen in production, but the contract
        // permits a null provider value).
        var response = AuthenticationResponse.WithMfaRequired(null);

        // assert
        response.MfaRequired.Should().BeTrue();
        response.MfaProvider.Should().BeNull();
        response.Token.Should().BeNull();
    }

    [Fact]
    public void Inherits_ApiResponse_AddErrorFlipsToUnsuccessful()
    {
        // arrange — verifies the factories don't break the inherited error pipeline. A regression
        // here would let controllers issue an MFA-required response and add an error and have
        // the response still report successful.
        var response = AuthenticationResponse.WithMfaRequired(MfaProviders.Email);

        // act
        response.AddError("k", "v");

        // assert
        response.IsSuccessful.Should().BeFalse();
        response.Errors.Should().NotBeNull().And.HaveCount(1);
    }
}
