using AuthenticationService.Shared.Models;
using AwesomeAssertions;

namespace AuthenticationService.Shared.Tests.Models;

/// <summary>
/// Pins the required/init contract on Token's identity-defining fields. Tokens are the
/// wire payload between auth and consumers; mutability would let a logging path
/// accidentally rewrite an issued JWT.
/// </summary>
public class TokenTests
{
    [Fact]
    public void RequiredAndOptionalFields_RoundTrip()
    {
        var expires = DateTime.UtcNow.AddMinutes(15);
        var refreshExpires = DateTime.UtcNow.AddDays(14);

        var token = new Token
        {
            Type = "Bearer",
            Value = "eyJh...",
            Expires = expires,
            RefreshToken = "0123456789abcdef",
            RefreshTokenExpiresAt = refreshExpires,
        };

        token.Type.Should().Be("Bearer");
        token.Value.Should().Be("eyJh...");
        token.Expires.Should().Be(expires);
        token.RefreshToken.Should().Be("0123456789abcdef");
        token.RefreshTokenExpiresAt.Should().Be(refreshExpires);
    }

    [Fact]
    public void OptionalFields_OmittedAreNull()
    {
        var token = new Token { Type = "Bearer", Value = "v" };

        token.Expires.Should().BeNull();
        token.RefreshToken.Should().BeNull();
        token.RefreshTokenExpiresAt.Should().BeNull();
    }
}
