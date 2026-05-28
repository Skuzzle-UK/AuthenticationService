namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// One row from the user-audit endpoint. Mirrors a Serilog event filtered to the target
/// user — event ID/name pin it to the canonical <c>SecurityEventIds</c> list.
/// </summary>
public class AuditEntryDto
{
    public DateTimeOffset Timestamp { get; set; }

    public int EventId { get; set; }

    public string EventName { get; set; } = default!;

    public string? IpAddress { get; set; }

    /// <summary>
    /// Information / Warning / Error / Critical — matches the Serilog level the source log used.
    /// </summary>
    public string Severity { get; set; } = default!;

    /// <summary>
    /// Remaining structured fields from the source event keyed by name (e.g. <c>FamilyId</c>, <c>Reason</c>, <c>Jti</c>).
    /// </summary>
    public IDictionary<string, string?> Fields { get; set; } = new Dictionary<string, string?>();
}
