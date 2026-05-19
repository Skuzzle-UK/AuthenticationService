using AuthenticationService.Entities;

namespace AuthenticationService.Services;

/// <summary>
/// Looks after OAuth client-credentials clients. Used by both the token endpoint
/// (<c>/oauth/token</c>) and the admin management endpoints (<c>/api/Admin/clients/*</c>).
///
/// <para>Two halves to the surface:</para>
/// <list type="bullet">
///   <item><description><b>Auth-side</b>: lookup, secret verification, scope validation. Hot path; called on every token request.</description></item>
///   <item><description><b>Admin-side</b>: create / rotate / disable / add-scope / remove-scope. Cold path; called from the admin endpoints.</description></item>
/// </list>
/// </summary>
public interface IClientService
{
    /// <summary>
    /// Looks up a client by id (the <c>client_id</c>). Returns null when the row doesn't
    /// exist OR is disabled — callers don't need to distinguish those at the token
    /// endpoint, and revealing the difference would let an attacker enumerate valid IDs.
    /// </summary>
    Task<Client?> FindActiveAsync(string clientId, CancellationToken ct);

    /// <summary>
    /// Constant-time verification of <paramref name="rawSecret"/> against the stored
    /// hash. Constant-time so timing differences don't leak whether a partial prefix
    /// match was detected.
    /// </summary>
    bool VerifySecret(Client client, string rawSecret);

    /// <summary>
    /// True iff the client has the given <paramref name="audience"/>/<paramref name="scope"/>
    /// row in <c>ClientScopes</c>. Caller invokes once per requested scope.
    /// </summary>
    Task<bool> HasScopeAsync(string clientId, string audience, string scope, CancellationToken ct);

    /// <summary>
    /// Stamps <c>LastUsedAt = now</c> on the client. Called after a successful token issue.
    /// Cheap UPDATE (single row, indexed by PK); fire-and-forget from the caller's
    /// perspective.
    /// </summary>
    Task TouchLastUsedAsync(string clientId, CancellationToken ct);

    // ─── Admin-side surface ─────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a new client + its initial scopes. The <paramref name="rawSecret"/>
    /// supplied here is the one-time-display secret — the caller (the admin endpoint)
    /// must echo it back in the response and forget about it. Only the hash is persisted.
    /// </summary>
    Task<Client> CreateAsync(string clientId, string name, string rawSecret, string? description, IEnumerable<(string Audience, string Scope)> scopes, CancellationToken ct);

    /// <summary>
    /// Overwrites the client's stored secret hash. Returns the existing client (with the
    /// updated hash) or null if no such client.
    /// </summary>
    Task<Client?> RotateSecretAsync(string clientId, string newRawSecret, CancellationToken ct);

    /// <summary>
    /// Soft-disable. Subsequent <c>FindActiveAsync</c> calls return null. The row stays
    /// for audit purposes; re-enabling means flipping the flag back via DB or a future
    /// admin endpoint.
    /// </summary>
    Task<bool> DisableAsync(string clientId, CancellationToken ct);

    /// <summary>Adds a (audience, scope) tuple. Idempotent — adding a tuple that already exists is a no-op.</summary>
    Task<bool> AddScopeAsync(string clientId, string audience, string scope, CancellationToken ct);

    /// <summary>Removes a (audience, scope) tuple. Returns false if no such tuple existed.</summary>
    Task<bool> RemoveScopeAsync(string clientId, string audience, string scope, CancellationToken ct);
}
