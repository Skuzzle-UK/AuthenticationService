using AuthenticationService.Logging;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace AuthenticationService.Tests.Logging;

/// <summary>
/// Serilog enricher attaches request-scoped <c>UserAgent</c> to log events. Three paths:
/// header present, header missing, no HttpContext (background work).
/// </summary>
public class HttpContextLogEnricherTests
{
    [Fact]
    public void Enrich_WithUserAgentHeader_AddsUserAgentProperty()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0)";
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(context);
        var enricher = new HttpContextLogEnricher(accessor);
        var logEvent = MakeEmptyLogEvent();

        enricher.Enrich(logEvent, new LogEventPropertyFactory());

        logEvent.Properties.Should().ContainKey("UserAgent");
        ((ScalarValue)logEvent.Properties["UserAgent"]).Value
            .Should().Be("Mozilla/5.0 (Windows NT 10.0)");
    }

    [Fact]
    public void Enrich_WithEmptyUserAgent_DoesNotAddProperty()
    {
        // Empty UA must skip rather than emit "UserAgent": "" — would pollute the log index.
        var context = new DefaultHttpContext();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(context);
        var enricher = new HttpContextLogEnricher(accessor);
        var logEvent = MakeEmptyLogEvent();

        enricher.Enrich(logEvent, new LogEventPropertyFactory());

        logEvent.Properties.Should().NotContainKey("UserAgent");
    }

    [Fact]
    public void Enrich_NoHttpContext_DoesNotThrowOrAddProperties()
    {
        // Background-worker path — throwing would crash the worker on every log line.
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns((HttpContext?)null);
        var enricher = new HttpContextLogEnricher(accessor);
        var logEvent = MakeEmptyLogEvent();

        var act = () => enricher.Enrich(logEvent, new LogEventPropertyFactory());

        act.Should().NotThrow();
        logEvent.Properties.Should().BeEmpty();
    }

    [Fact]
    public void Enrich_PropertyAlreadyExistsOnLogEvent_DoesNotOverwrite()
    {
        // AddPropertyIfAbsent semantics — switching to overwrite would mask caller-attached values.
        var context = new DefaultHttpContext();
        context.Request.Headers["User-Agent"] = "from-request";
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(context);
        var enricher = new HttpContextLogEnricher(accessor);
        var logEvent = MakeEmptyLogEvent();
        logEvent.AddPropertyIfAbsent(new LogEventProperty("UserAgent", new ScalarValue("from-scope")));

        enricher.Enrich(logEvent, new LogEventPropertyFactory());

        ((ScalarValue)logEvent.Properties["UserAgent"]).Value.Should().Be("from-scope");
    }

    private static LogEvent MakeEmptyLogEvent() => new(
        DateTimeOffset.UtcNow,
        LogEventLevel.Information,
        exception: null,
        new MessageTemplate("test", []),
        []);

    /// <summary>
    /// Minimal property factory — Serilog's default isn't exposed in the public API.
    /// </summary>
    private sealed class LogEventPropertyFactory : ILogEventPropertyFactory
    {
        public LogEventProperty CreateProperty(string name, object? value, bool destructureObjects = false)
            => new(name, new ScalarValue(value));
    }
}
