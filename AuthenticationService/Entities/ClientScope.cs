using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// One (audience, scope) tuple a <see cref="Client"/> is permitted to request at the
/// OAuth token endpoint. The token endpoint checks every requested scope has a matching
/// row before issuing a JWT.
/// </summary>
public class ClientScope
{
    public int Id { get; set; }

    /// <summary>
    /// FK to <see cref="Client.Id"/>. Cascade-deletes — disabling a client removes its scopes via the soft-delete; hard-deleting via the admin endpoint cleans up the rows.
    /// </summary>
    [Required, MaxLength(255)]
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// The <c>aud</c> claim stamped on tokens carrying this scope.
    /// </summary>
    [Required, MaxLength(255)]
    public string Audience { get; set; } = default!;

    /// <summary>
    /// Scope name. Resource-action convention by design — least privilege.
    /// </summary>
    [Required, MaxLength(255)]
    public string Scope { get; set; } = default!;

    public Client? Client { get; set; }
}
