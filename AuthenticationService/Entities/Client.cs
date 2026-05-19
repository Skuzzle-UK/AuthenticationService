using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// A service-to-service consumer. Holds the client_id (the primary key), a secret hash
/// for verifying credentials at the OAuth token endpoint, and per-incident metadata
/// (created / last-used / disabled).
///
/// <para>The actual scopes a client is allowed to request live in <see cref="ClientScope"/>
/// — each scope is a (Audience, Scope) tuple. A client can have many scopes, each scoped
/// to a single resource service.</para>
///
/// <para>Secrets are stored as hashes only. The plaintext is shown to the admin exactly
/// once at creation / rotation; if it's lost, the only remediation is rotation.</para>
/// </summary>
public class Client
{
    /// <summary>The <c>client_id</c> used in OAuth. Stable, human-readable (e.g., <c>inventory-api</c>, <c>orders-batch-worker</c>).</summary>
    [Required, MaxLength(255)]
    public string Id { get; set; } = default!;

    /// <summary>Human-readable label for admin UI / audit logs.</summary>
    [Required, MaxLength(255)]
    public string Name { get; set; } = default!;

    /// <summary>BCrypt / Identity-style hash of the client secret. Plaintext is never stored.</summary>
    [Required, MaxLength(512)]
    public string ClientSecretHash { get; set; } = default!;

    /// <summary>
    /// Soft-disable flag. Set by admin via <c>POST /api/Admin/clients/{id}/disable</c> when
    /// retiring a client. Token-issuance rejects disabled clients with
    /// <c>invalid_client</c> (doesn't reveal whether the client exists or just isn't
    /// allowed to authenticate).
    /// </summary>
    public bool IsDisabled { get; set; }

    /// <summary>Stamped at object construction. Used for sort + audit display.</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Updated on every successful token issue. Null until the first token has been issued.
    /// Useful for admin "which clients are actually being used?" / "this client hasn't
    /// used its credentials in 90 days, can we retire it?" questions.
    /// </summary>
    public DateTime? LastUsedAt { get; set; }

    /// <summary>Free-text note shown in admin UI — what's this client for, who owns it.</summary>
    public string? Description { get; set; }

    /// <summary>Navigation: the (Audience, Scope) tuples this client is permitted to request.</summary>
    public List<ClientScope> Scopes { get; set; } = [];
}
