namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Thin client shape returned from <c>GET /api/Admin/clients</c>. Deliberately small —
/// full detail (scopes list) comes from the dedicated detail endpoint to keep list
/// payloads cheap. Never includes the secret hash.
/// </summary>
public class ClientSummaryDto
{
    public string Id { get; set; } = default!;
    public string Name { get; set; } = default!;
    public bool IsDisabled { get; set; }
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Null until the client has issued its first token. Useful for "which clients are actually being used?" admin queries.
    /// </summary>
    public DateTime? LastUsedAt { get; set; }

    public string? Description { get; set; }
}
