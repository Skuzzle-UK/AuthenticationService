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
}
