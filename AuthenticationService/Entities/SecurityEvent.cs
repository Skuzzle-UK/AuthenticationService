using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// Audit row populated by <c>SecurityEventSink</c> from EventId-tagged log events. Queried
/// by the admin audit endpoint and SIEM. Pruned on schedule by <c>DataRetentionCleanupService</c>.
/// </summary>
public class SecurityEvent
{
    public long Id { get; set; }

    public DateTime Timestamp { get; set; }

    /// <summary>
    /// The numeric <c>EventId.Id</c> from <c>SecurityEventIds</c>.
    /// </summary>
    public int EventId { get; set; }

    /// <summary>
    /// The string <c>EventId.Name</c> from <c>SecurityEventIds</c> (e.g. <c>LoginSucceeded</c>).
    /// </summary>
    [Required, MaxLength(100)]
    public string EventName { get; set; } = default!;

    /// <summary>
    /// Serilog log level — Information / Warning / Error / Critical.
    /// </summary>
    [Required, MaxLength(20)]
    public string Level { get; set; } = default!;

    /// <summary>
    /// Rendered message string (template + filled-in property values).
    /// </summary>
    [MaxLength(2000)]
    public string? Message { get; set; }

    /// <summary>
    /// Indexed with Timestamp for the audit endpoint's user-scoped query.
    /// </summary>
    [MaxLength(450)]
    public string? UserId { get; set; }

    /// <summary>
    /// Extracted from the log event's <c>{IpAddress}</c> property when present.
    /// </summary>
    [MaxLength(45)]
    public string? IpAddress { get; set; }

    /// <summary>
    /// Residual properties JSON-encoded; excludes the extracted columns.
    /// </summary>
    public string? PropertiesJson { get; set; }
}
