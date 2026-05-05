#pragma warning disable

using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

public class RevokedToken
{
    [Required]
    public string TokenJti { get; set; }

    public string UserId { get; set; }

    public DateTime? ExpiresAt { get; set; }

    /// <summary>IP from which the revocation request originated. Audit only.</summary>
    [MaxLength(45)]
    public string? RevokedFromIp { get; set; }

    /// <summary>When the revocation occurred. Audit only.</summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>Why the token was revoked. See <c>RevocationReasons</c> for canonical values.</summary>
    [MaxLength(50)]
    public string? RevocationReason { get; set; }
}
