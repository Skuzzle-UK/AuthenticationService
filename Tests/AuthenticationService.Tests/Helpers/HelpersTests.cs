using AuthenticationService.Constants;
using AuthenticationService.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthenticationService.Tests.Helpers;

/// <summary>
/// URI helpers build links that ship to users via email; QR helpers build the PNG that enrols
/// authenticator apps. Tests pin shape + bytes.
/// </summary>
public class HelpersTests
{
    // ─── AccountHelpers ─────────────────────────────────────────────────────────────────

    [Fact]
    public void AccountHelpers_GenerateResetPasswordUri_AppendsTokenAndEmailQueryParams()
    {
        // arrange
        const string email = "alice@example.com";
        const string token = "abc123";
        const string callback = "https://app.example.com/reset";

        // act
        var uri = AccountHelpers.GenerateResetPasswordUri(email, token, callback);

        // assert
        uri.Should().StartWith(callback);
        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed[UriConstants.Token].ToString().Should().Be(token);
        parsed[UriConstants.Email].ToString().Should().Be(email);
        parsed.Should().HaveCount(2, because: "reset-password URIs only carry token + email — no lockout marker.");
    }

    [Fact]
    public void AccountHelpers_GenerateResetPasswordUri_PreservesExistingQueryParams()
    {
        // arrange — operator-supplied callback may carry params (campaign tracking, tenant hints), helper must append not clobber.
        const string callback = "https://app.example.com/reset?source=email";

        // act
        var uri = AccountHelpers.GenerateResetPasswordUri("a@b.com", "tok", callback);

        // assert
        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed["source"].ToString().Should().Be("email");
        parsed[UriConstants.Token].ToString().Should().Be("tok");
        parsed[UriConstants.Email].ToString().Should().Be("a@b.com");
    }

    [Fact]
    public void AccountHelpers_GenerateLockoutUri_AppendsLockoutTrueMarker()
    {
        // arrange
        const string email = "a@b.com";
        const string token = "tok";
        const string callback = "https://app.example.com/handle";

        // act
        var uri = AccountHelpers.GenerateLockoutUri(email, token, callback);

        // assert
        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed[UriConstants.Token].ToString().Should().Be(token);
        parsed[UriConstants.Email].ToString().Should().Be(email);
        parsed[UriConstants.Lockout].ToString().Should().Be(UriConstants.True);
        parsed.Should().HaveCount(3);
    }

    [Fact]
    public void AccountHelpers_GenerateResetPasswordUri_UrlEncodesSpecialCharacters()
    {
        // arrange — emails / tokens may contain '+' or '/', pins that the helper uses QueryHelpers rather than naive concat.
        const string email = "alice+filter@example.com";
        const string token = "abc/def=";
        const string callback = "https://app.example.com/reset";

        // act
        var uri = AccountHelpers.GenerateResetPasswordUri(email, token, callback);

        // assert
        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed[UriConstants.Email].ToString().Should().Be(email);
        parsed[UriConstants.Token].ToString().Should().Be(token);
    }

    // ─── QrCodeHelpers ──────────────────────────────────────────────────────────────────

    [Fact]
    public void QrCodeHelpers_NewPng_ReturnsValidPngBytes()
    {
        // arrange
        const string email = "alice@example.com";
        const string key = "JBSWY3DPEHPK3PXP";

        // act
        var png = QrCodeHelpers.NewPng(email, key);

        // assert — PNG signature: 89 50 4E 47 0D 0A 1A 0A.
        png.Should().NotBeNull();
        png.Length.Should().BeGreaterThan(8);
        png.Take(8).Should().Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
    }

    [Fact]
    public void QrCodeHelpers_NewPng_DifferentInputs_ProduceDifferentImages()
    {
        // act
        var first = QrCodeHelpers.NewPng("alice@example.com", "JBSWY3DPEHPK3PXP");
        var second = QrCodeHelpers.NewPng("bob@example.com", "ABCDEFGHIJKLMNOP");

        // assert
        first.Should().NotEqual(second);
    }

    [Fact]
    public void QrCodeHelpers_NewPng_HandlesEmailsWithSpecialCharacters()
    {
        // act — '+' in an email needs URL encoding inside the otpauth:// payload or QR readers see "alice filter@..."
        var png = QrCodeHelpers.NewPng("alice+filter@example.com", "JBSWY3DPEHPK3PXP");

        // assert
        png.Take(8).Should().Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
    }
}
