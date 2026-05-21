using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Logging;
using AuthenticationService.Storage;
using AwesomeAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Serilog.Events;
using Serilog.Parsing;

namespace AuthenticationService.Tests.Logging;

/// <summary>
/// Drives <see cref="SecurityEventSink"/> with hand-crafted <see cref="LogEvent"/>s (no Serilog
/// plumbing). Covers the EventId filter, column extraction, JSON shape, and DB-write swallow.
/// </summary>
public class SecurityEventSinkTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly ServiceProvider _provider;
    private readonly IServiceScopeFactory _scopeFactory;

    public SecurityEventSinkTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        var services = new ServiceCollection();
        services.AddDbContext<DatabaseContext>(opt => opt.UseSqlite(_connection));
        _provider = services.BuildServiceProvider();

        using var scope = _provider.CreateScope();
        scope.ServiceProvider.GetRequiredService<DatabaseContext>().Database.EnsureCreated();

        _scopeFactory = _provider.GetRequiredService<IServiceScopeFactory>();
    }

    [Fact]
    public void Emit_NoEventIdProperty_SkipsWrite()
    {
        var sink = new SecurityEventSink(_scopeFactory);
        var logEvent = MakeLogEvent(LogEventLevel.Information, eventId: null);

        sink.Emit(logEvent);

        using var scope = _provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        db.SecurityEvents.Should().BeEmpty(
            because: "events without an EventId property are not security-audit events and must not pollute the table");
    }

    [Theory]
    [InlineData(0, "Unset")]
    [InlineData(999, "JustBelowRange")]
    [InlineData(7000, "JustAboveRange")]
    [InlineData(20402, "EfMigrationApplied")]
    public void Emit_EventIdOutsideSecurityRange_SkipsWrite(int eventIdValue, string eventName)
    {
        // Filter persists only SecurityEventIds 1000–6000. EF migration events at startup would deadlock the sink
        // against the migration creating the SecurityEvents table.
        var sink = new SecurityEventSink(_scopeFactory);
        var logEvent = MakeLogEvent(LogEventLevel.Information, eventId: (eventIdValue, eventName));

        sink.Emit(logEvent);

        using var scope = _provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        db.SecurityEvents.Should().BeEmpty();
    }

    [Fact]
    public void Emit_NonZeroEventId_PersistsRowWithExtractedColumns()
    {
        var sink = new SecurityEventSink(_scopeFactory);
        var props = new Dictionary<string, object?>
        {
            ["UserId"] = "user-1",
            ["IpAddress"] = "10.0.0.5",
            ["Reason"] = "bad_credentials",
        };
        var logEvent = MakeLogEvent(LogEventLevel.Warning, eventId: (SecurityEventIds.LoginFailed.Id, "LoginFailed"), props);

        sink.Emit(logEvent);

        using var scope = _provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        var row = db.SecurityEvents.Single();

        row.EventId.Should().Be(SecurityEventIds.LoginFailed.Id);
        row.EventName.Should().Be("LoginFailed");
        row.UserId.Should().Be("user-1");
        row.IpAddress.Should().Be("10.0.0.5");
        row.Level.Should().Be("Warning");
        row.PropertiesJson.Should().NotBeNull()
            .And.Subject!.Should().Contain("\"Reason\"")
            .And.Contain("bad_credentials",
                because: "residual properties beyond UserId/IpAddress should be JSON-encoded");
    }

    [Fact]
    public void Emit_PropertiesJson_ExcludesExtractedColumns()
    {
        // UserId and IpAddress are their own columns — shouldn't also live in the JSON blob.
        var sink = new SecurityEventSink(_scopeFactory);
        var props = new Dictionary<string, object?>
        {
            ["UserId"] = "user-1",
            ["IpAddress"] = "10.0.0.5",
            ["FamilyId"] = "fam-99",
        };
        var logEvent = MakeLogEvent(LogEventLevel.Information, eventId: (1001, "LoginSucceeded"), props);

        sink.Emit(logEvent);

        using var scope = _provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
        var row = db.SecurityEvents.Single();

        row.PropertiesJson.Should().Contain("FamilyId");
        row.PropertiesJson.Should().NotContain("\"UserId\"",
            because: "UserId is already its own column");
        row.PropertiesJson.Should().NotContain("\"IpAddress\"",
            because: "IpAddress is already its own column");
    }

    [Fact]
    public void Emit_DbWriteFails_SwallowsExceptionDoesNotThrow()
    {
        // Force SaveChanges to throw — auditing failure must never bring down the request that triggered the log.
        _connection.Close();
        var sink = new SecurityEventSink(_scopeFactory);
        var logEvent = MakeLogEvent(LogEventLevel.Fatal, eventId: (1008, "RefreshTokenReuseDetected"),
            properties: new Dictionary<string, object?> { ["UserId"] = "u1" });

        var act = () => sink.Emit(logEvent);

        act.Should().NotThrow(
            because: "audit-table write failure must never propagate out of the sink");
    }

    // ─── helpers ────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Hand-crafted Serilog LogEvent — the EventId tuple matches the (Id, Name) shape
    /// Microsoft.Extensions.Logging uses when forwarding to Serilog.
    /// </summary>
    private static LogEvent MakeLogEvent(
        LogEventLevel level,
        (int Id, string Name)? eventId,
        IDictionary<string, object?>? properties = null)
    {
        var parser = new MessageTemplateParser();
        var template = parser.Parse("test event");

        var allProps = new List<LogEventProperty>();
        if (eventId is { } e)
        {
            allProps.Add(new LogEventProperty("EventId", new StructureValue(new[]
            {
                new LogEventProperty("Id", new ScalarValue(e.Id)),
                new LogEventProperty("Name", new ScalarValue(e.Name)),
            })));
        }
        if (properties is not null)
        {
            foreach (var (k, v) in properties)
            {
                allProps.Add(new LogEventProperty(k, new ScalarValue(v)));
            }
        }

        return new LogEvent(
            timestamp: DateTimeOffset.UtcNow,
            level: level,
            exception: null,
            messageTemplate: template,
            properties: allProps);
    }

    public void Dispose()
    {
        try { _provider.Dispose(); } catch { }
        try { _connection.Dispose(); } catch { }
    }
}
