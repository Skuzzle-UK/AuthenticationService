using AuthenticationService.Entities;

namespace AuthenticationService.Services;

/// <summary>
/// OAuth client-credentials client lookup, verification, and admin CRUD. Used by the token
/// endpoint (hot path) and the admin management endpoints.
/// </summary>
public interface IClientService
{
    /// <summary>
    /// Returns null when the row is missing OR disabled — token endpoint doesn't need to
    /// distinguish, and revealing the difference would enable client_id enumeration.
    /// </summary>
    Task<Client?> FindActiveAsync(string clientId, CancellationToken ct);

    /// <summary>
    /// Constant-time secret verification so timing doesn't leak prefix matches.
    /// </summary>
    bool VerifySecret(Client client, string rawSecret);

    /// <summary>
    /// True if the client has the given <paramref name="audience"/>/<paramref name="scope"/>
    /// row in <c>ClientScopes</c>. Caller invokes once per requested scope.
    /// </summary>
    Task<bool> HasScopeAsync(string clientId, string audience, string scope, CancellationToken ct);

    /// <summary>
    /// Stamps <c>LastUsedAt = now</c>. Cheap single-row UPDATE.
    /// </summary>
    Task TouchLastUsedAsync(string clientId, CancellationToken ct);

    // ─── Admin-side surface ─────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a client with its initial scopes. <paramref name="rawSecret"/> is the
    /// one-time-display secret — only the hash is persisted.
    /// </summary>
    Task<Client> CreateAsync(string clientId, string name, string rawSecret, string? description, IEnumerable<(string Audience, string Scope)> scopes, CancellationToken ct);

    /// <summary>
    /// Overwrites the secret hash. Returns null if no such client.
    /// </summary>
    Task<Client?> RotateSecretAsync(string clientId, string newRawSecret, CancellationToken ct);

    /// <summary>
    /// Soft-disable. Row stays for audit; re-enable via DB.
    /// </summary>
    Task<bool> DisableAsync(string clientId, CancellationToken ct);

    /// <summary>
    /// Idempotent — duplicate insert is a no-op.
    /// </summary>
    Task<bool> AddScopeAsync(string clientId, string audience, string scope, CancellationToken ct);

    /// <summary>
    /// Returns false if no such tuple existed.
    /// </summary>
    Task<bool> RemoveScopeAsync(string clientId, string audience, string scope, CancellationToken ct);
}
