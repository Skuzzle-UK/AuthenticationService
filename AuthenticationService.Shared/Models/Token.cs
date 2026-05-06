namespace AuthenticationService.Shared.Models;

/// <summary>
/// The access + refresh token pair returned to the client after a successful login or
/// refresh. <see cref="Value"/> goes in the <c>Authorization</c> header on subsequent
/// requests; <see cref="RefreshToken"/> is sent back to <c>/refresh</c> to swap the pair
/// for a new one once the access token expires.
/// </summary>
public class Token
{
    /// <summary>Token scheme — currently always <c>"Bearer"</c>.</summary>
    public required string Type { get; init; }

    /// <summary>The access token (the JWT itself).</summary>
    public required string Value { get; init; }

    /// <summary>When the access token expires.</summary>
    public DateTime? Expires { get; init; }

    /// <summary>The refresh token (an opaque random string — keep it secret).</summary>
    public string? RefreshToken { get; init; }

    /// <summary>When the refresh token expires.</summary>
    public DateTime? RefreshTokenExpiresAt { get; init; }
}
