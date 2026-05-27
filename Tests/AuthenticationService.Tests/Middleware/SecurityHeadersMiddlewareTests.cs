using AuthenticationService.Middleware;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;

namespace AuthenticationService.Tests.Middleware;

/// <summary>
/// Pins every defence-in-depth response header value — regressions silently weaken the security posture
/// of the bundled Razor pages against XSS / clickjacking / MIME-confusion / referer leakage.
/// </summary>
public class SecurityHeadersMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_AddsAllExpectedSecurityHeaders()
    {
        // arrange
        var nextCalled = false;
        Task next(HttpContext _) { nextCalled = true; return Task.CompletedTask; }
        var middleware = new SecurityHeadersMiddleware(next);
        var context = new DefaultHttpContext();

        // act
        await middleware.InvokeAsync(context);

        // assert
        var headers = context.Response.Headers;
        nextCalled.Should().BeTrue(because: "middleware always passes through; it's purely additive.");

        headers.ContentSecurityPolicy.ToString().Should()
            .Contain("default-src 'self'", because: "everything outside our origin is denied unless explicitly allowed below.")
            .And.Contain("frame-ancestors 'none'", because: "pages cannot be embedded in any frame — clickjacking defence.")
            .And.Contain("form-action 'self'", because: "forms can only POST back to our origin — defence against credential-stealing form hijack.")
            .And.Contain("base-uri 'self'", because: "blocks injection of <base> that would redirect relative URLs to attacker-controlled origin.")
            .And.NotContain("'unsafe-inline'", because: "Razor pages load JS from external files; adding 'unsafe-inline' back would mean inline <script> or onclick= snuck in — review the Pages tree.");

        headers.XContentTypeOptions.ToString().Should().Be("nosniff",
            because: "stops MIME sniffing — defence against the browser executing untyped content as script.");

        headers.XFrameOptions.ToString().Should().Be("DENY",
            because: "no framing under any circumstance — same intent as frame-ancestors 'none' but for legacy browsers.");

        headers["Referrer-Policy"].ToString().Should().Be("strict-origin-when-cross-origin",
            because: "stops the Referer header leaking sensitive URL fragments (e.g. reset-password tokens) to third-party sites.");

        headers["Permissions-Policy"].ToString().Should()
            .Contain("camera=()", because: "auth service has no business with the camera; closes the door if XSS ever lands.")
            .And.Contain("microphone=()")
            .And.Contain("geolocation=()")
            .And.Contain("payment=()")
            .And.Contain("usb=()")
            .And.Contain("fullscreen=()");
    }

    [Fact]
    public async Task InvokeAsync_PassesThroughEvenWhenHeadersAlreadyExist()
    {
        // arrange — pinned that the IHeaderDictionary indexer overwrites, a switch to .Add would throw on duplicate.
        var nextCalled = false;
        Task next(HttpContext _) { nextCalled = true; return Task.CompletedTask; }
        var middleware = new SecurityHeadersMiddleware(next);
        var context = new DefaultHttpContext();
        context.Response.Headers.XFrameOptions = "SAMEORIGIN";

        // act + assert
        var act = async () => await middleware.InvokeAsync(context);

        await act.Should().NotThrowAsync();
        context.Response.Headers.XFrameOptions.ToString().Should().Be("DENY",
            because: "middleware overrides any earlier-set value — its policy wins.");
        nextCalled.Should().BeTrue();
    }
}
