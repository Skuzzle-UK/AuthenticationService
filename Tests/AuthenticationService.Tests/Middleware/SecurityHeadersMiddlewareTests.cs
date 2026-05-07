using AuthenticationService.Middleware;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;

namespace AuthenticationService.Tests.Middleware;

/// <summary>
/// <para>The middleware adds defence-in-depth response headers — CSP, X-Frame-Options,
/// X-Content-Type-Options, Referrer-Policy, Permissions-Policy. These headers materially
/// harden the Razor pages (reset-password / lock-account / action-complete) against XSS,
/// clickjacking, MIME-confusion, and referer leakage.</para>
///
/// <para>Tests pin every header value because (a) regressions silently weaken the security
/// posture and (b) any change should be deliberate (e.g. CSP sources adjusted along with a
/// page change that needs more permissive policy).</para>
/// </summary>
public class SecurityHeadersMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_AddsAllExpectedSecurityHeaders()
    {
        // arrange
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };
        var middleware = new SecurityHeadersMiddleware(next);
        var context = new DefaultHttpContext();

        // act
        await middleware.InvokeAsync(context);

        // assert — every header that defends a specific browser-side attack class.
        var headers = context.Response.Headers;
        nextCalled.Should().BeTrue(because: "middleware always passes through; it's purely additive.");

        headers.ContentSecurityPolicy.ToString().Should()
            .Contain("default-src 'self'", because: "everything outside our origin is denied unless explicitly allowed below.")
            .And.Contain("frame-ancestors 'none'", because: "pages cannot be embedded in any frame — clickjacking defence.")
            .And.Contain("form-action 'self'", because: "forms can only POST back to our origin — defence against credential-stealing form hijack.")
            .And.Contain("base-uri 'self'", because: "blocks injection of <base> that would redirect relative URLs to attacker-controlled origin.");

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
        // arrange — middleware shouldn't crash if a downstream handler set headers first.
        // ASP.NET's IHeaderDictionary indexer overwrites — pinned here so a switch to .Add
        // (which throws on duplicate) would be caught.
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };
        var middleware = new SecurityHeadersMiddleware(next);
        var context = new DefaultHttpContext();
        context.Response.Headers.XFrameOptions = "SAMEORIGIN";

        // act
        var act = async () => await middleware.InvokeAsync(context);

        // assert
        await act.Should().NotThrowAsync();
        context.Response.Headers.XFrameOptions.ToString().Should().Be("DENY",
            because: "middleware overrides any earlier-set value — its policy wins.");
        nextCalled.Should().BeTrue();
    }
}
