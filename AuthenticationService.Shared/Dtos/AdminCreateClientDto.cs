using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Body for <c>POST /api/Admin/clients</c>. The auth service generates the secret;
/// admin doesn't supply one (and can't choose it). Initial scopes are optional but
/// recommended — a client with no scopes can't request a useful token.
/// </summary>
public class AdminCreateClientDto
{
    /// <summary>The <c>client_id</c>. Stable identifier; admins pick this. Convention: lower-case kebab-case (<c>inventory-api</c>, <c>orders-batch-worker</c>).</summary>
    [Required, MaxLength(255)]
    public string? Id { get; set; }

    /// <summary>Human-readable label for admin UI / audit logs.</summary>
    [Required, MaxLength(255)]
    public string? Name { get; set; }

    /// <summary>Optional note explaining what the client is for, who owns it.</summary>
    public string? Description { get; set; }

    /// <summary>Optional initial scope list. Each item is a (Audience, Scope) tuple.</summary>
    public IList<AdminClientScopeDto>? Scopes { get; set; }
}

/// <summary>A single (audience, scope) tuple — used by client-create and add-scope requests.</summary>
public class AdminClientScopeDto
{
    [Required, MaxLength(255)]
    public string? Audience { get; set; }

    [Required, MaxLength(255)]
    public string? Scope { get; set; }
}
