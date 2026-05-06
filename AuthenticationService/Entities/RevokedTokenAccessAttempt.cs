#pragma warning disable

using AuthenticationService.Enums;

namespace AuthenticationService.Entities;

/// <summary>
/// One row per replay of an already-revoked access token. Written by
/// <see cref="Middleware.RevokedTokenMiddleware"/> when JwtBearer's signature/expiry
/// check would have let the token through but our deny-list rejected it. The intended
/// consumers are the (still-pending) threshold-escalation worker and SIEM forwarding
/// — anything that needs to see "the same stolen token is being hammered against us"
/// over time.
///
/// <para><see cref="Severity"/> is set by the recording method:
/// <c>Low</c> when the underlying token's natural <c>exp</c> has already passed (JwtBearer
/// would have rejected it anyway, the deny-list just got there first), <c>Medium</c> when
/// the token is still within its lifetime (the deny-list is the only thing stopping it).</para>
/// </summary>
public class RevokedTokenAccessAttempt
{
    public int Id { get; set; }
    public string TokenJti { get; set; }
    public string UserId { get; set; }
    public string IpAddress { get; set; }
    public DateTime CreatedAt { get; set; }
    public Severity Severity { get; set; }
}
