using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Dtos.Response;

/// <summary>
/// <para><see cref="EnableMfaResponse"/> has two constructors: a parameterless one (for
/// frameworks that need to instantiate it from an empty body) and a payload one used in
/// happy-path responses. Both paths must leave the inherited <see cref="ApiResponse"/>
/// envelope in the default-successful state.</para>
/// </summary>
public class EnableMfaResponseTests
{
    [Fact]
    public void DefaultConstructor_ProducesEmptyResponseInSuccessfulState()
    {
        // arrange / act
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
        // arrange — typical authenticator-app enrolment: QR code + base32 key for users who
        // can't scan the QR.
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
        // arrange / act — email + phone enrolment doesn't produce a QR/key (the secret is
        // delivered out-of-band via the messaging channel). Tests confirm those fields stay
        // null when the optional args are omitted.
        var response = new EnableMfaResponse(provider);

        // assert
        response.EnabledMfaProvider.Should().Be(provider);
        response.QrCode.Should().BeNull();
        response.Key.Should().BeNull();
    }
}
