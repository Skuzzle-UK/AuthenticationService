using System.Text.Json;
using AuthenticationService.Entities;
using AuthenticationService.Storage;
using Serilog.Core;
using Serilog.Debugging;
using Serilog.Events;

namespace AuthenticationService.Logging;

/// <summary>
/// Persists <see cref="Microsoft.Extensions.Logging.EventId"/>-tagged log events to the
/// <c>SecurityEvents</c> table. Filters to the security EventId range so EF/Identity/ASP.NET
/// events stay out (their write attempts would deadlock startup against the very migration
/// that creates the table). DB errors swallow into <see cref="SelfLog"/> — losing an audit
/// row beats 500ing the request.
/// </summary>
public sealed class SecurityEventSink : ILogEventSink
{
    /// <summary>
    /// Lower bound (inclusive) of the security EventId range. Matches the 1000s "Authentication" block in <c>SecurityEventIds</c>.
    /// </summary>
    public const int MinSecurityEventId = 1000;

    /// <summary>
    /// Exclusive upper bound. Leaves headroom above the 6000s s2s block.
    /// </summary>
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

    // Returns false when the event has no EventId in the security range — those don't
    // belong in the audit table.
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

        // Range filter — excludes the 0 sentinel and EF/Identity/ASP.NET events.
        if (eventId < MinSecurityEventId || eventId >= MaxSecurityEventId)
        {
            return false;
        }

        var userId = TryGetScalarString(logEvent, "UserId");
        var ipAddress = TryGetScalarString(logEvent, "IpAddress");

        // Residual JSON — everything not extracted into its own column.
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

    private static object? RenderPropertyValue(LogEventPropertyValue value) =>
        value switch
        {
            ScalarValue { Value: null } => null,
            ScalarValue { Value: string s } => s,
            ScalarValue scalar => scalar.Value?.ToString(),
            _ => value.ToString().Trim('"'),
        };
}
