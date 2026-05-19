using System.Text.Json;
using AuthenticationService.Entities;
using AuthenticationService.Storage;
using Serilog.Core;
using Serilog.Debugging;
using Serilog.Events;

namespace AuthenticationService.Logging;

/// <summary>
/// Custom Serilog sink that persists <see cref="Microsoft.Extensions.Logging.EventId"/>-tagged
/// log events to the <c>SecurityEvents</c> table via the existing
/// <see cref="DatabaseContext"/>. Powers the admin audit endpoint.
///
/// <para>Filter: only events whose <c>EventId.Id</c> falls in the security range
/// (<see cref="MinSecurityEventId"/>..<see cref="MaxSecurityEventId"/>) are persisted —
/// matching the ranges <c>SecurityEventIds</c> reserves (1000s authentication, 2000s
/// registration, 3000s account, 4000s token, 5000s admin). EF Core / ASP.NET Core /
/// Identity log events that happen to carry an EventId fall outside this range and
/// are ignored — critical at startup where EF logs about migrations would otherwise
/// try to write to the SecurityEvents table that the very migration is creating
/// (deadlocks startup).</para>
///
/// <para>Writes synchronously per event via a fresh scope. Volume is bounded (at most a
/// handful of security events per request, request rate is bounded by auth-flow limits)
/// so per-event INSERT cost is invisible against everything else. If volume grows, swap
/// for a batched implementation via <c>Channel</c> + a hosted-service drain.</para>
///
/// <para>Failure handling: any DB error is swallowed and written to Serilog's
/// <see cref="SelfLog"/> — losing an audit row is bad but bringing the request down
/// because the audit table is unreachable is worse. The console + OTLP sinks still
/// capture the original event so the audit trail isn't entirely gone.</para>
/// </summary>
public sealed class SecurityEventSink : ILogEventSink
{
    /// <summary>Lower bound (inclusive) of the security EventId range. Matches the 1000s "Authentication" block in <c>SecurityEventIds</c>.</summary>
    public const int MinSecurityEventId = 1000;

    /// <summary>Upper bound (exclusive) of the security EventId range. Leaves room above the current 6000s "Service-to-service auth" block for future categories without re-tuning the filter.</summary>
    public const int MaxSecurityEventId = 7000;

    private readonly IServiceScopeFactory _scopeFactory;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    public SecurityEventSink(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public void Emit(LogEvent logEvent)
    {
        if (!TryBuildEntity(logEvent, out var entity))
        {
            return;
        }

        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
            db.SecurityEvents.Add(entity);
            db.SaveChanges();
        }
        catch (Exception ex)
        {
            SelfLog.WriteLine("SecurityEventSink failed to persist event {0}: {1}", entity.EventName, ex);
        }
    }

    /// <summary>
    /// Maps a Serilog <see cref="LogEvent"/> into a <see cref="SecurityEvent"/> entity.
    /// Returns false when the event has no <c>EventId</c> property (i.e. wasn't tagged
    /// with one of our <c>SecurityEventIds</c>) — those don't belong in the audit table.
    /// </summary>
    private static bool TryBuildEntity(LogEvent logEvent, out SecurityEvent entity)
    {
        entity = default!;

        if (!logEvent.Properties.TryGetValue("EventId", out var eventIdProperty))
        {
            return false;
        }

        // Serilog renders ILogger EventId as a StructureValue with Id + Name members.
        if (eventIdProperty is not StructureValue eventIdStructure)
        {
            return false;
        }

        var eventId = 0;
        var eventName = string.Empty;
        foreach (var member in eventIdStructure.Properties)
        {
            if (member.Name == "Id" && member.Value is ScalarValue { Value: int id })
            {
                eventId = id;
            }
            else if (member.Name == "Name" && member.Value is ScalarValue { Value: string name })
            {
                eventName = name;
            }
        }

        // Filter to the security EventId range. Skips:
        //   - eventId == 0 (the "no event id" sentinel)
        //   - EF Core / ASP.NET Core / Identity events that carry their own EventIds
        //     (typically 10000+ or sub-1000 ranges) — none of those belong in the audit
        //     trail, and during startup, persisting EF migration events would deadlock
        //     against the very migration creating the SecurityEvents table.
        if (eventId < MinSecurityEventId || eventId >= MaxSecurityEventId)
        {
            return false;
        }

        var userId = TryGetScalarString(logEvent, "UserId");
        var ipAddress = TryGetScalarString(logEvent, "IpAddress");

        // Build the residual-properties JSON — everything except the two extracted columns
        // (UserId, IpAddress) and the EventId structure that lives in its own columns.
        var residualProperties = new Dictionary<string, object?>();
        foreach (var (key, value) in logEvent.Properties)
        {
            if (key is "UserId" or "IpAddress" or "EventId")
            {
                continue;
            }
            residualProperties[key] = RenderPropertyValue(value);
        }

        entity = new SecurityEvent
        {
            Timestamp = logEvent.Timestamp.UtcDateTime,
            EventId = eventId,
            EventName = string.IsNullOrEmpty(eventName) ? eventId.ToString() : eventName,
            Level = logEvent.Level.ToString(),
            Message = logEvent.RenderMessage(),
            UserId = userId,
            IpAddress = ipAddress,
            PropertiesJson = residualProperties.Count > 0
                ? JsonSerializer.Serialize(residualProperties, JsonOptions)
                : null,
        };
        return true;
    }

    private static string? TryGetScalarString(LogEvent logEvent, string key)
    {
        if (!logEvent.Properties.TryGetValue(key, out var value) || value is not ScalarValue scalar)
        {
            return null;
        }
        return scalar.Value?.ToString();
    }

    /// <summary>Renders a Serilog property value into a JSON-friendly shape. Strings stay strings; other scalars are coerced to string; complex types fall back to the rendered representation.</summary>
    private static object? RenderPropertyValue(LogEventPropertyValue value) =>
        value switch
        {
            ScalarValue { Value: null } => null,
            ScalarValue { Value: string s } => s,
            ScalarValue scalar => scalar.Value?.ToString(),
            _ => value.ToString().Trim('"'),
        };
}
