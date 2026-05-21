#pragma warning disable

using AuthenticationService.Enums;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// One row per replay of an already-revoked access token. Written by
/// <see cref="Middleware.RevokedTokenMiddleware"/>; consumed by the threshold-escalation
/// worker and SIEM. <see cref="Severity"/>: <c>Low</c> if the token's natural exp has
/// passed (JwtBearer would have rejected it anyway), <c>Medium</c> if still live.
/// </summary>
public class RevokedTokenAccessAttempt
{
    public int Id { get; set; }
    public string TokenJti { get; set; }
    public string UserId { get; set; }
    public string IpAddress { get; set; }

    [MaxLength(512)]
    public string? UserAgent { get; set; }

    public DateTime CreatedAt { get; set; }
    public Severity Severity { get; set; }
}
