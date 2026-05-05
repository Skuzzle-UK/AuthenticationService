using AuthenticationService.Shared.Models;

namespace AuthenticationService.Services;

/// <summary>
/// Outcome of a refresh-token rotation attempt. The controller pattern-matches on the
/// concrete type to choose the response.
/// </summary>
public abstract record RefreshResult
{
    /// <summary>Rotation succeeded; <paramref name="Token"/> is the new access + refresh pair.</summary>
    public sealed record Success(Token Token) : RefreshResult;

    /// <summary>Refresh token did not match any row for this user. Generic 401.</summary>
    public sealed record NotFound : RefreshResult;

    /// <summary>Refresh token row exists but its <c>ExpiresAt</c> has passed. 401.</summary>
    public sealed record Expired : RefreshResult;

    /// <summary>
    /// The presented refresh token was already consumed. Treated as theft: every refresh-token
    /// family for the user has been revoked and the security stamp rotated by the time this is
    /// returned. Caller should respond with a generic 401 — don't tip off the attacker.
    /// </summary>
    public sealed record Reused(Guid FamilyId) : RefreshResult;
}
