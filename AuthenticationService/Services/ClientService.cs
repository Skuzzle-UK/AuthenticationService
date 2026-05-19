using AuthenticationService.Entities;
using AuthenticationService.Storage;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Services;

/// <inheritdoc />
public class ClientService : IClientService
{
    private readonly DatabaseContext _context;
    private readonly IPasswordHasher<Client> _hasher;

    public ClientService(DatabaseContext context, IPasswordHasher<Client> hasher)
    {
        _context = context;
        _hasher = hasher;
    }

    // ─── Auth-side surface ──────────────────────────────────────────────────────────

    public async Task<Client?> FindActiveAsync(string clientId, CancellationToken ct) =>
        await _context.Clients
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == clientId && !c.IsDisabled, ct);

    public bool VerifySecret(Client client, string rawSecret)
    {
        // PasswordHasher's VerifyHashedPassword does a constant-time compare on the
        // hash bytes; piggy-back on it so we share the same algorithm + iteration count
        // as user-password verification.
        var result = _hasher.VerifyHashedPassword(client, client.ClientSecretHash, rawSecret);
        return result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded;
    }

    public async Task<bool> HasScopeAsync(string clientId, string audience, string scope, CancellationToken ct) =>
        await _context.ClientScopes
            .AsNoTracking()
            .AnyAsync(s => s.ClientId == clientId && s.Audience == audience && s.Scope == scope, ct);

    public async Task TouchLastUsedAsync(string clientId, CancellationToken ct)
    {
        // ExecuteUpdate so we don't have to load the entity. The token endpoint already
        // has the client_id from the request — no point pulling the whole row just to
        // bump a timestamp.
        var now = DateTime.UtcNow;
        await _context.Clients
            .Where(c => c.Id == clientId)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.LastUsedAt, now), ct);
    }

    // ─── Admin-side surface ─────────────────────────────────────────────────────────

    public async Task<Client> CreateAsync(
        string clientId,
        string name,
        string rawSecret,
        string? description,
        IEnumerable<(string Audience, string Scope)> scopes,
        CancellationToken ct)
    {
        var client = new Client
        {
            Id = clientId,
            Name = name,
            Description = description,
            IsDisabled = false,
        };
        client.ClientSecretHash = _hasher.HashPassword(client, rawSecret);

        foreach (var (audience, scope) in scopes)
        {
            client.Scopes.Add(new ClientScope
            {
                ClientId = clientId,
                Audience = audience,
                Scope = scope,
            });
        }

        _context.Clients.Add(client);
        await _context.SaveChangesAsync(ct);
        return client;
    }

    public async Task<Client?> RotateSecretAsync(string clientId, string newRawSecret, CancellationToken ct)
    {
        var client = await _context.Clients.FirstOrDefaultAsync(c => c.Id == clientId, ct);
        if (client is null)
        {
            return null;
        }

        client.ClientSecretHash = _hasher.HashPassword(client, newRawSecret);
        await _context.SaveChangesAsync(ct);
        return client;
    }

    public async Task<bool> DisableAsync(string clientId, CancellationToken ct)
    {
        var rows = await _context.Clients
            .Where(c => c.Id == clientId && !c.IsDisabled)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.IsDisabled, true), ct);
        return rows > 0;
    }

    public async Task<bool> AddScopeAsync(string clientId, string audience, string scope, CancellationToken ct)
    {
        // Idempotent: if the tuple already exists, return false (no-op) but treat as
        // success-shaped at the controller layer. The unique index on
        // (ClientId, Audience, Scope) would otherwise throw on duplicate insert.
        var exists = await _context.ClientScopes
            .AnyAsync(s => s.ClientId == clientId && s.Audience == audience && s.Scope == scope, ct);
        if (exists)
        {
            return false;
        }

        _context.ClientScopes.Add(new ClientScope
        {
            ClientId = clientId,
            Audience = audience,
            Scope = scope,
        });
        await _context.SaveChangesAsync(ct);
        return true;
    }

    public async Task<bool> RemoveScopeAsync(string clientId, string audience, string scope, CancellationToken ct)
    {
        var rows = await _context.ClientScopes
            .Where(s => s.ClientId == clientId && s.Audience == audience && s.Scope == scope)
            .ExecuteDeleteAsync(ct);
        return rows > 0;
    }
}
