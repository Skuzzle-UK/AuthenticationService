#pragma warning disable CS8618 // Uninitialised non-nullable — EF Core sets properties via the change tracker on materialisation.

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

    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>
    /// IP from which the revocation request originated. Audit only.
    /// </summary>
    [MaxLength(45)]
    public string? RevokedFromIp { get; set; }

    /// <summary>
    /// When the revocation occurred. Audit only.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>
    /// Why the token was revoked. See <c>RevocationReasons</c> for canonical values.
    /// </summary>
    [MaxLength(50)]
    public string? RevocationReason { get; set; }

    /// <summary>
    /// Non-null prevents the threshold-escalation worker re-firing the warn event each sweep.
    /// </summary>
    public DateTimeOffset? WarnedAt { get; set; }

    /// <summary>
    /// Non-null prevents the worker re-locking and re-emailing each sweep.
    /// </summary>
    public DateTimeOffset? LockedAt { get; set; }
}
