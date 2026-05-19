using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

/// <summary>
/// One row per <see cref="Microsoft.Extensions.Logging.EventId"/>-tagged log event the
/// service emits. Populated by <c>SecurityEventSink</c> (custom Serilog sink) so the
/// existing <c>_logger.LogXxx(SecurityEventIds.X, ...)</c> emit sites don't need to be
/// duplicated.
///
/// <para>The admin audit endpoint queries this table by <see cref="UserId"/> to surface
/// the security activity for a single user. Other consumers (SIEM, ops dashboards) can
/// query it directly.</para>
///
/// <para>The table is bounded by the existing <c>DataRetentionCleanupService</c> via a
/// retention setting — old rows are deleted on a schedule.</para>
/// </summary>
public class SecurityEvent
{
    public long Id { get; set; }

    public DateTime Timestamp { get; set; }

    /// <summary>The numeric <c>EventId.Id</c> from <c>SecurityEventIds</c>.</summary>
    public int EventId { get; set; }

    /// <summary>The string <c>EventId.Name</c> from <c>SecurityEventIds</c> (e.g. <c>LoginSucceeded</c>).</summary>
    [Required, MaxLength(100)]
    public string EventName { get; set; } = default!;

    /// <summary>Serilog log level — Information / Warning / Error / Critical.</summary>
    [Required, MaxLength(20)]
    public string Level { get; set; } = default!;

    /// <summary>Rendered message string (template + filled-in property values).</summary>
    [MaxLength(2000)]
    public string? Message { get; set; }

    /// <summary>
    /// Extracted from the log event's <c>{UserId}</c> property. Indexed alongside
    /// Timestamp to support the audit endpoint's "events for user X, most recent first"
    /// query. Null for events that don't carry a user id (rare).
    /// </summary>
    [MaxLength(450)]
    public string? UserId { get; set; }

    /// <summary>Extracted from the log event's <c>{IpAddress}</c> property when present.</summary>
    [MaxLength(45)]
    public string? IpAddress { get; set; }

    /// <summary>
    /// Remaining structured properties from the log event, JSON-encoded. Excludes the
    /// extracted columns (UserId, IpAddress) to avoid duplication.
    /// </summary>
    public string? PropertiesJson { get; set; }
}
