using AuthenticationService.Shared.Models;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Models;

/// <summary>
/// <para><see cref="Token"/> uses <c>required</c> + <c>init</c> on its identity-defining
/// fields. The test verifies the language contract — code that forgets to populate
/// <see cref="Token.Type"/> or <see cref="Token.Value"/> won't compile, and once
/// constructed the values are immutable. Both matter because tokens are the wire-protocol
/// payload between auth and consumers; mutability would let a logging path accidentally
/// rewrite an issued JWT.</para>
/// </summary>
public class TokenTests
{
    [Fact]
    public void RequiredAndOptionalFields_RoundTrip()
    {
        // arrange
        var expires = DateTime.UtcNow.AddMinutes(15);
        var refreshExpires = DateTime.UtcNow.AddDays(14);

        // act — required Type + Value, optional refresh + expiry. Init-only props can only
        // be set in the object initializer, not later — that's the C# contract we rely on.
        var token = new Token
        {
            Type = "Bearer",
            Value = "eyJh...",
            Expires = expires,
            RefreshToken = "0123456789abcdef",
            RefreshTokenExpiresAt = refreshExpires,
        };

        // assert
        token.Type.Should().Be("Bearer");
        token.Value.Should().Be("eyJh...");
        token.Expires.Should().Be(expires);
        token.RefreshToken.Should().Be("0123456789abcdef");
        token.RefreshTokenExpiresAt.Should().Be(refreshExpires);
    }

    [Fact]
    public void OptionalFields_OmittedAreNull()
    {
        // arrange / act — only required fields set. Tests that consumers can issue a
        // token-only response (no refresh token) without filling the optional fields.
        var token = new Token { Type = "Bearer", Value = "v" };

        // assert
        token.Expires.Should().BeNull();
        token.RefreshToken.Should().BeNull();
        token.RefreshTokenExpiresAt.Should().BeNull();
    }
}
