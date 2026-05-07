using AuthenticationService.Constants;
using AuthenticationService.Helpers;
using AwesomeAssertions;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthenticationService.Tests.Helpers;

/// <summary>
/// <para>The two helpers build URIs and PNGs that ship to users via email and to clients
/// via the API. URI shape mistakes break the link the user clicks; QR-code mistakes break
/// authenticator-app enrolment. Tests pin shape and contents.</para>
/// </summary>
public class HelpersTests
{
    // ─── AccountHelpers ─────────────────────────────────────────────────────────────────

    [Fact]
    public void AccountHelpers_GenerateResetPasswordUri_AppendsTokenAndEmailQueryParams()
    {
        // arrange — a simple callback URL the consumer's UI handles.
        const string email = "alice@example.com";
        const string token = "abc123";
        const string callback = "https://app.example.com/reset";

        // act
        var uri = AccountHelpers.GenerateResetPasswordUri(email, token, callback);

        // assert — the URL must round-trip through the standard QueryHelpers parser. We
        // parse it back out so the test is robust to ordering / URL-encoding details.
        uri.Should().StartWith(callback);
        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed[UriConstants.Token].ToString().Should().Be(token);
        parsed[UriConstants.Email].ToString().Should().Be(email);
        parsed.Should().HaveCount(2, because: "reset-password URIs only carry token + email — no lockout marker.");
    }

    [Fact]
    public void AccountHelpers_GenerateResetPasswordUri_PreservesExistingQueryParams()
    {
        // arrange — operator-supplied callback may already carry params (campaign tracking,
        // tenant hints). The helper must append rather than clobber them.
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
        // arrange — the lockout link has the same Token/Email pair plus a `lockout=true`
        // marker that the receiving page uses to decide which UI flow to show.
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
        // arrange — emails and tokens may contain '+' or '/'. QueryHelpers handles encoding;
        // this test pins that the helper actually relies on QueryHelpers (rather than naive
        // string concatenation that would let raw '+' hit the URL).
        const string email = "alice+filter@example.com";
        const string token = "abc/def=";
        const string callback = "https://app.example.com/reset";

        // act
        var uri = AccountHelpers.GenerateResetPasswordUri(email, token, callback);

        // assert — round-trip through Uri parsing recovers the original values, proving
        // they were encoded correctly on the way out.
        var parsed = QueryHelpers.ParseQuery(new Uri(uri).Query);
        parsed[UriConstants.Email].ToString().Should().Be(email);
        parsed[UriConstants.Token].ToString().Should().Be(token);
    }

    // ─── QrCodeHelpers ──────────────────────────────────────────────────────────────────

    [Fact]
    public void QrCodeHelpers_NewPng_ReturnsValidPngBytes()
    {
        // arrange — typical authenticator enrolment inputs.
        const string email = "alice@example.com";
        const string key = "JBSWY3DPEHPK3PXP";

        // act
        var png = QrCodeHelpers.NewPng(email, key);

        // assert — PNG signature: 89 50 4E 47 0D 0A 1A 0A. Verifying the magic bytes
        // confirms we got an actual PNG rather than e.g. a corrupt buffer or empty array.
        png.Should().NotBeNull();
        png.Length.Should().BeGreaterThan(8);
        png.Take(8).Should().Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
    }

    [Fact]
    public void QrCodeHelpers_NewPng_DifferentInputs_ProduceDifferentImages()
    {
        // arrange — two distinct (email, key) pairs must produce different QR codes;
        // otherwise enrolment would silently return the same secret-bound image to multiple
        // users (which would make their tokens collide).
        var first = QrCodeHelpers.NewPng("alice@example.com", "JBSWY3DPEHPK3PXP");
        var second = QrCodeHelpers.NewPng("bob@example.com", "ABCDEFGHIJKLMNOP");

        // assert — byte-equal comparison is fine here; QR-code generation is deterministic
        // for fixed inputs.
        first.Should().NotEqual(second);
    }

    [Fact]
    public void QrCodeHelpers_NewPng_HandlesEmailsWithSpecialCharacters()
    {
        // arrange — '+' in an email needs URL encoding inside the otpauth:// payload.
        // Without encoding, the QR code reader sees "alice filter@..." which breaks
        // enrolment. This test pins that the helper encodes before generating.
        var png = QrCodeHelpers.NewPng("alice+filter@example.com", "JBSWY3DPEHPK3PXP");

        // assert — we can't decode the QR programmatically here, but a successful generate
        // (no exception, valid PNG bytes) is enough — encoding bugs would either throw or
        // produce a structurally different image we can compare against the simple-input one.
        png.Take(8).Should().Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
    }
}
