namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Full client detail returned from <c>GET /api/Admin/clients/{id}</c>. Includes the
/// (Audience, Scope) tuple list so admins can review what a client is authorised to
/// request without making a second call. Never includes the secret hash.
/// </summary>
public class ClientDetailDto : ApiResponse
{
    public string Id { get; set; } = default!;
    public string Name { get; set; } = default!;
    public bool IsDisabled { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public string? Description { get; set; }

    /// <summary>The (Audience, Scope) tuples this client is permitted to request.</summary>
    public IList<AdminClientScopeDto> Scopes { get; set; } = [];
}
