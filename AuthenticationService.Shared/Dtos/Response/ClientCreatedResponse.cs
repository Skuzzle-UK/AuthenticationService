namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Response from <c>POST /api/Admin/clients</c> and <c>/rotate-secret</c>. Carries the
/// plaintext secret <em>once</em> — the admin has to capture it now; we only persist the
/// hash. Lost secrets can't be recovered, only rotated.
/// </summary>
public class ClientCreatedResponse : ApiResponse
{
    public string Id { get; set; } = default!;
    public string Name { get; set; } = default!;

    /// <summary>
    /// Plaintext client secret. Shown once — DB stores only the hash. Treat as sensitive credential material.
    /// </summary>
    public string ClientSecret { get; set; } = default!;
}
