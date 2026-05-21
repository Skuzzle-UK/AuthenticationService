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
        const string email = "alice@example.com";
        const string token = "abc123";
        const string callback = "https://app.example.com/reset";

        var uri = AccountHelpers.GenerateResetPasswordUri(email, token, callback);

        uri.Should().StartWith(callback);
        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed[UriConstants.Token].ToString().Should().Be(token);
        parsed[UriConstants.Email].ToString().Should().Be(email);
        parsed.Should().HaveCount(2, because: "reset-password URIs only carry token + email — no lockout marker.");
    }

    [Fact]
    public void AccountHelpers_GenerateResetPasswordUri_PreservesExistingQueryParams()
    {
        // Operator-supplied callback may carry params (campaign tracking, tenant hints) — helper must append not clobber.
        const string callback = "https://app.example.com/reset?source=email";

        var uri = AccountHelpers.GenerateResetPasswordUri("a@b.com", "tok", callback);

        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed["source"].ToString().Should().Be("email");
        parsed[UriConstants.Token].ToString().Should().Be("tok");
        parsed[UriConstants.Email].ToString().Should().Be("a@b.com");
    }

    [Fact]
    public void AccountHelpers_GenerateLockoutUri_AppendsLockoutTrueMarker()
    {
        const string email = "a@b.com";
        const string token = "tok";
        const string callback = "https://app.example.com/handle";

        var uri = AccountHelpers.GenerateLockoutUri(email, token, callback);

        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed[UriConstants.Token].ToString().Should().Be(token);
        parsed[UriConstants.Email].ToString().Should().Be(email);
        parsed[UriConstants.Lockout].ToString().Should().Be(UriConstants.True);
        parsed.Should().HaveCount(3);
    }

    [Fact]
    public void AccountHelpers_GenerateResetPasswordUri_UrlEncodesSpecialCharacters()
    {
        // Emails / tokens may contain '+' or '/' — pins that the helper uses QueryHelpers rather than naive concat.
        const string email = "alice+filter@example.com";
        const string token = "abc/def=";
        const string callback = "https://app.example.com/reset";

        var uri = AccountHelpers.GenerateResetPasswordUri(email, token, callback);

        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed[UriConstants.Email].ToString().Should().Be(email);
        parsed[UriConstants.Token].ToString().Should().Be(token);
    }

    // ─── QrCodeHelpers ──────────────────────────────────────────────────────────────────

    [Fact]
    public void QrCodeHelpers_NewPng_ReturnsValidPngBytes()
    {
        const string email = "alice@example.com";
        const string key = "JBSWY3DPEHPK3PXP";

        var png = QrCodeHelpers.NewPng(email, key);

        // PNG signature: 89 50 4E 47 0D 0A 1A 0A.
        png.Should().NotBeNull();
        png.Length.Should().BeGreaterThan(8);
        png.Take(8).Should().Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
    }

    [Fact]
    public void QrCodeHelpers_NewPng_DifferentInputs_ProduceDifferentImages()
    {
        var first = QrCodeHelpers.NewPng("alice@example.com", "JBSWY3DPEHPK3PXP");
        var second = QrCodeHelpers.NewPng("bob@example.com", "ABCDEFGHIJKLMNOP");

        first.Should().NotEqual(second);
    }

    [Fact]
    public void QrCodeHelpers_NewPng_HandlesEmailsWithSpecialCharacters()
    {
        // '+' in an email needs URL encoding inside the otpauth:// payload or QR readers see "alice filter@..."
        var png = QrCodeHelpers.NewPng("alice+filter@example.com", "JBSWY3DPEHPK3PXP");

        png.Take(8).Should().Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
    }
}
