using AuthenticationService.Extensions;
using AwesomeAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using System.Net;
using System.Text.Json;

namespace AuthenticationService.Tests.Extensions;

/// <summary>
/// Covers the production exception-handler wiring (Tier 0 / B2): unhandled exceptions
/// must surface as RFC 7807 ProblemDetails JSON, not blank 500s. Spins up a minimal
/// WebApplication with the same registrations + middleware order as the real app.
/// </summary>
public class ProblemDetailsExceptionHandlerTests
{
    [Fact]
    public async Task UnhandledException_ReturnsProblemDetailsJson()
    {
        await using var app = BuildApp();
        await app.StartAsync();
        var client = app.GetTestClient();

        var response = await client.GetAsync("/boom");

        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("status").GetInt32().Should().Be(500);
        doc.RootElement.GetProperty("title").GetString().Should().NotBeNullOrWhiteSpace();
        doc.RootElement.GetProperty("traceId").GetString().Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task EmptyNotFound_AlsoProducesProblemDetails()
    {
        // UseStatusCodePages() should fill in a body for an otherwise-empty 404 too.
        await using var app = BuildApp();
        await app.StartAsync();
        var client = app.GetTestClient();

        var response = await client.GetAsync("/no-such-route");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");

        var body = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        doc.RootElement.GetProperty("status").GetInt32().Should().Be(404);
        doc.RootElement.GetProperty("traceId").GetString().Should().NotBeNullOrWhiteSpace();
    }

    // Mirrors WebApplicationExtensions' production pipeline:
    // AddProblemDetailsConfiguration() + UseExceptionHandler() + UseStatusCodePages().
    private static WebApplication BuildApp()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddProblemDetailsConfiguration();

        var app = builder.Build();
        app.UseExceptionHandler();
        app.UseStatusCodePages();
        app.MapGet("/boom", Boom);
        return app;
    }

    // Method group with an explicit return type — gives the Minimal API overload an
    // unambiguous Delegate to bind to (lambda-with-throw has no inferable return type).
    private static string Boom() =>
        throw new InvalidOperationException("deliberate test failure");
}
