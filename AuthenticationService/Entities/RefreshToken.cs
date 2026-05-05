using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// One row per refresh token issued. Tokens within the same session share a
/// <see cref="FamilyId"/>; rotation chains via <see cref="ReplacedByTokenId"/>.
/// Used by JWTService to validate refreshes, detect reuse, and support per-device
/// session management.
/// </summary>
public class RefreshToken
{
    public Guid Id { get; set; }

    [Required]
    public string UserId { get; set; } = default!;

    public User User { get; set; } = default!;

    /// <summary>
    /// SHA-256 of the raw token bytes (base64url). Never store the raw token.
    /// </summary>
    [Required]
    public string TokenHash { get; set; } = default!;

    /// <summary>
    /// Shared across every rotation of one session. Used as the OIDC <c>sid</c> claim.
    /// </summary>
    public Guid FamilyId { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Null while the token is still usable. Set when consumed by rotation, logout, or revocation.
    /// </summary>
    public DateTime? ConsumedAt { get; set; }

    /// <summary>
    /// When consumed by rotation, points at the next token in the family. Null otherwise.
    /// </summary>
    public Guid? ReplacedByTokenId { get; set; }

    /// <summary>
    /// "logout" | "logout_all" | "password_change" | "reuse_detected" | etc. Null = consumed by normal rotation.
    /// </summary>
    [MaxLength(50)]
    public string? RevocationReason { get; set; }

    /// <summary>
    /// IP at issue time. Audit only.
    /// </summary>
    [MaxLength(45)]
    public string? CreatedFromIp { get; set; }
}
