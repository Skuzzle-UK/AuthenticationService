#pragma warning disable

using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// One row per access-token <c>jti</c> that's been revoked before its natural expiry.
/// Acts as the deny-list <see cref="Middleware.RevokedTokenMiddleware"/> consults on
/// every request. Rows are pruned by <c>DataRetentionService</c> once the underlying
/// token's own expiry has passed (the JwtBearer expiry check would reject it anyway).
/// </summary>
public class RevokedToken
{
    [Required]
    public string TokenJti { get; set; }

    public string UserId { get; set; }

    public DateTime? ExpiresAt { get; set; }

    /// <summary>
    /// IP from which the revocation request originated. Audit only.
    /// </summary>
    [MaxLength(45)]
    public string? RevokedFromIp { get; set; }

    /// <summary>
    /// When the revocation occurred. Audit only.
    /// </summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// Why the token was revoked. See <c>RevocationReasons</c> for canonical values.
    /// </summary>
    [MaxLength(50)]
    public string? RevocationReason { get; set; }

    /// <summary>
    /// When the threshold-escalation worker first emitted the warn-level SIEM event for
    /// repeated replay of this token. Null until the warn threshold is crossed; non-null
    /// after, which prevents re-firing the warn event on every subsequent sweep.
    /// </summary>
    public DateTime? WarnedAt { get; set; }

    /// <summary>
    /// When the threshold-escalation worker locked the account due to sustained replay
    /// of this token. Null until the lock threshold is crossed; non-null after, which
    /// prevents re-locking and re-emailing on every subsequent sweep.
    /// </summary>
    public DateTime? LockedAt { get; set; }
}
