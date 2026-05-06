using Serilog.Core;
using Serilog.Events;

namespace AuthenticationService.Logging;

/// <summary>
/// Serilog enricher that attaches request-scoped fields (currently <c>UserAgent</c>) to
/// every log event emitted during an HTTP request. Picked up automatically by Serilog's
/// <c>ReadFrom.Services(services)</c> in <c>Program.Main</c> as long as it's registered in
/// DI as <see cref="ILogEventEnricher"/>.
/// </summary>
public sealed class HttpContextLogEnricher : ILogEventEnricher
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public HttpContextLogEnricher(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            return;
        }

        var userAgent = httpContext.Request.Headers.UserAgent.ToString();
        if (!string.IsNullOrEmpty(userAgent))
        {
            logEvent.AddPropertyIfAbsent(propertyFactory.CreateProperty("UserAgent", userAgent));
        }
    }
}
