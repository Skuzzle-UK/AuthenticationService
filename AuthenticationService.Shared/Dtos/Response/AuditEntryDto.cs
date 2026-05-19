namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// One row from the user-audit endpoint. Shape mirrors a single Serilog event filtered
/// to the target user — the event ID + name pin it to the canonical
/// <c>SecurityEventIds</c> list; the structured fields carry whatever context that
/// specific event emits (IP, FamilyId, Reason, etc.).
/// </summary>
public class AuditEntryDto
{
    public DateTime Timestamp { get; set; }

    public int EventId { get; set; }

    public string EventName { get; set; } = default!;

    public string? IpAddress { get; set; }

    /// <summary>Information / Warning / Error / Critical — matches the Serilog level the source log used.</summary>
    public string Severity { get; set; } = default!;

    /// <summary>
    /// Remaining structured fields from the source event keyed by name (e.g.
    /// <c>FamilyId</c>, <c>Reason</c>, <c>Jti</c>). Values may be null when the field
    /// wasn't set on that particular event.
    /// </summary>
    public IDictionary<string, string?> Fields { get; set; } = new Dictionary<string, string?>();
}
