using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// A service-to-service consumer. Scopes (audience, scope tuples) live in
/// <see cref="ClientScope"/>. Secrets are stored hashed; plaintext is shown to the admin
/// exactly once at creation / rotation.
/// </summary>
public class Client
{
    /// <summary>
    /// The <c>client_id</c> used in OAuth. Stable, human-readable (e.g., <c>inventory-api</c>, <c>orders-batch-worker</c>).
    /// </summary>
    [Required, MaxLength(255)]
    public string Id { get; set; } = default!;

    /// <summary>
    /// Human-readable label for admin UI / audit logs.
    /// </summary>
    [Required, MaxLength(255)]
    public string Name { get; set; } = default!;

    /// <summary>
    /// BCrypt / Identity-style hash of the client secret. Plaintext is never stored.
    /// </summary>
    [Required, MaxLength(512)]
    public string ClientSecretHash { get; set; } = default!;

    /// <summary>
    /// Soft-disable flag. Token-issuance rejects disabled clients with <c>invalid_client</c>
    /// — deliberately doesn't reveal whether the client exists.
    /// </summary>
    public bool IsDisabled { get; set; }

    /// <summary>
    /// Stamped at object construction. Used for sort + audit display.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Updated on every successful token issue. Null until the first issuance.
    /// </summary>
    public DateTimeOffset? LastUsedAt { get; set; }

    /// <summary>
    /// Free-text note for the admin UI.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Navigation: the (Audience, Scope) tuples this client is permitted to request.
    /// </summary>
    public List<ClientScope> Scopes { get; set; } = [];
}
