using Serilog.Core;
using Serilog.Events;

namespace AuthenticationService.Logging;

/// <summary>
/// Serilog enricher that attaches request-scoped fields (currently <c>UserAgent</c>) to
/// every log event during a request. Picked up by <c>ReadFrom.Services</c> in Program.Main.
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
