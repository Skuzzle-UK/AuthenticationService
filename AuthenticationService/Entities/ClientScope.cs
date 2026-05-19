using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// One (audience, scope) tuple a <see cref="Client"/> is permitted to request at the
/// OAuth token endpoint. A client gets a row per scope per audience; the token endpoint
/// checks every requested scope has a matching row before issuing a JWT.
///
/// <para>Example: <c>inventory-api</c> client might have these rows:</para>
/// <list type="bullet">
///   <item><description>(inventory-api, inventory.read)</description></item>
///   <item><description>(inventory-api, inventory.write)</description></item>
///   <item><description>(orders-api, orders.read)</description></item>
/// </list>
/// <para>So it can request a token for <c>inventory-api</c> with read+write, or a
/// separate token for <c>orders-api</c> with just read.</para>
/// </summary>
public class ClientScope
{
    public int Id { get; set; }

    /// <summary>FK to <see cref="Client.Id"/>. Cascade-deletes — disabling a client removes its scopes via the soft-delete; hard-deleting via the admin endpoint cleans up the rows.</summary>
    [Required, MaxLength(255)]
    public string ClientId { get; set; } = default!;

    /// <summary>The <c>aud</c> claim that will be on tokens carrying this scope (e.g., <c>inventory-api</c>).</summary>
    [Required, MaxLength(255)]
    public string Audience { get; set; } = default!;

    /// <summary>The scope name (e.g., <c>inventory.read</c>). Resource-action convention by design — least privilege.</summary>
    [Required, MaxLength(255)]
    public string Scope { get; set; } = default!;

    public Client? Client { get; set; }
}
