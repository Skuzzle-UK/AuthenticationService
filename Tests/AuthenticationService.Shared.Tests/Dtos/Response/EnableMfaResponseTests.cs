using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Dtos.Response;

/// <summary>
/// Pins both constructors of EnableMfaResponse (parameterless + payload) and verifies
/// each leaves the inherited ApiResponse in the default-successful state.
/// </summary>
public class EnableMfaResponseTests
{
    [Fact]
    public void DefaultConstructor_ProducesEmptyResponseInSuccessfulState()
    {
        // act
        var response = new EnableMfaResponse();

        // assert
        response.QrCode.Should().BeNull();
        response.Key.Should().BeNull();
        response.EnabledMfaProvider.Should().BeNull();
        response.IsSuccessful.Should().BeTrue();
    }

    [Fact]
    public void PayloadConstructor_AuthenticatorProvider_StoresQrAndKey()
    {
        // arrange
        var qr = new byte[] { 0x89, 0x50, 0x4E, 0x47 }; // PNG header
        var key = "JBSWY3DPEHPK3PXP";

        // act
        var response = new EnableMfaResponse(MfaProviders.Authenticator, qr, key);

        // assert
        response.EnabledMfaProvider.Should().Be(MfaProviders.Authenticator);
        response.QrCode.Should().BeSameAs(qr);
        response.Key.Should().Be(key);
    }

    [Theory]
    [InlineData(MfaProviders.Email)]
    [InlineData(MfaProviders.Phone)]
    public void PayloadConstructor_NonAuthenticatorProviders_LeaveQrAndKeyDefaulted(MfaProviders provider)
    {
        // act — email + phone deliver the secret out-of-band, so no QR/key.
        var response = new EnableMfaResponse(provider);

        // assert
        response.EnabledMfaProvider.Should().Be(provider);
        response.QrCode.Should().BeNull();
        response.Key.Should().BeNull();
    }
}
