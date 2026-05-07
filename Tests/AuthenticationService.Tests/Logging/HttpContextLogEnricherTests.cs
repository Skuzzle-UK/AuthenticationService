using AuthenticationService.Logging;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace AuthenticationService.Tests.Logging;

/// <summary>
/// <para>Serilog enricher attaches request-scoped fields to every log event during a
/// request. The single field today is <c>UserAgent</c>. The enricher has three paths:</para>
/// <list type="bullet">
///   <item><description>HttpContext present + UserAgent header → property added</description></item>
///   <item><description>HttpContext present but UserAgent header empty/null → no-op (don't pollute logs with empty fields)</description></item>
///   <item><description>HttpContext null (background work running outside a request) → no-op</description></item>
/// </list>
/// </summary>
public class HttpContextLogEnricherTests
{
    [Fact]
    public void Enrich_WithUserAgentHeader_AddsUserAgentProperty()
    {
        // arrange — typical browser request.
        var context = new DefaultHttpContext();
        context.Request.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0)";
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(context);
        var enricher = new HttpContextLogEnricher(accessor);
        var logEvent = MakeEmptyLogEvent();

        // act
        enricher.Enrich(logEvent, new LogEventPropertyFactory());

        // assert
        logEvent.Properties.Should().ContainKey("UserAgent");
        ((ScalarValue)logEvent.Properties["UserAgent"]).Value
            .Should().Be("Mozilla/5.0 (Windows NT 10.0)");
    }

    [Fact]
    public void Enrich_WithEmptyUserAgent_DoesNotAddProperty()
    {
        // arrange — no UA on the request (machine-to-machine clients, certain monitoring
        // probes). Enricher must skip rather than emit "UserAgent": "" — that pollutes
        // the log index with empty fields.
        var context = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(context);
        var enricher = new HttpContextLogEnricher(accessor);
        var logEvent = MakeEmptyLogEvent();

        // act
        enricher.Enrich(logEvent, new LogEventPropertyFactory());

        // assert
        logEvent.Properties.Should().NotContainKey("UserAgent");
    }

    [Fact]
    public void Enrich_NoHttpContext_DoesNotThrowOrAddProperties()
    {
        // arrange — background-worker / DI-scope-without-request path. Enricher must
        // gracefully no-op; throwing would crash the worker on every log line.
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns((HttpContext?)null);
        var enricher = new HttpContextLogEnricher(accessor);
        var logEvent = MakeEmptyLogEvent();

        // act
        var act = () => enricher.Enrich(logEvent, new LogEventPropertyFactory());

        // assert
        act.Should().NotThrow();
        logEvent.Properties.Should().BeEmpty();
    }

    [Fact]
    public void Enrich_PropertyAlreadyExistsOnLogEvent_DoesNotOverwrite()
    {
        // arrange — Serilog's AddPropertyIfAbsent semantics. If something else upstream
        // (e.g. a manual log scope) already attached a UserAgent property, we leave it.
        // Tests pin AddPropertyIfAbsent vs AddOrUpdateProperty — switching to overwrite
        // would silently mask any caller-attached value.
        var context = new DefaultHttpContext();
        context.Request.Headers["User-Agent"] = "from-request";
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(context);
        var enricher = new HttpContextLogEnricher(accessor);
        var logEvent = MakeEmptyLogEvent();
        logEvent.AddPropertyIfAbsent(new LogEventProperty("UserAgent", new ScalarValue("from-scope")));

        // act
        enricher.Enrich(logEvent, new LogEventPropertyFactory());

        // assert
        ((ScalarValue)logEvent.Properties["UserAgent"]).Value.Should().Be("from-scope");
    }

    private static LogEvent MakeEmptyLogEvent() => new(
        DateTimeOffset.UtcNow,
        LogEventLevel.Information,
        exception: null,
        new MessageTemplate("test", []),
        []);

    /// <summary>
    /// Minimal property factory for the test — Serilog ships an internal default but it's
    /// not exposed in the public API, so we build our own.
    /// </summary>
    private sealed class LogEventPropertyFactory : ILogEventPropertyFactory
    {
        public LogEventProperty CreateProperty(string name, object? value, bool destructureObjects = false)
            => new(name, new ScalarValue(value));
    }
}
