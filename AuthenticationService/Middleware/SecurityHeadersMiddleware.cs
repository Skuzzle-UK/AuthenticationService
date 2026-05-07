namespace AuthenticationService.Middleware;

/// <summary>
/// Adds the standard set of security-related response headers that browsers honour as
/// defence-in-depth backstops. Most of these don't matter for the auth service's API
/// endpoints (machine-to-machine clients ignore them) but they materially harden the
/// Razor pages — <c>/ResetPassword</c>, <c>/LockAccount</c>, <c>/ActionComplete</c>.
///
/// <para>Headers added:</para>
/// <list type="bullet">
///   <item><description><c>Content-Security-Policy</c>: locks down what scripts / styles / images can load. Defends against XSS even if a malicious payload reaches our HTML.</description></item>
///   <item><description><c>X-Content-Type-Options: nosniff</c>: stops browsers second-guessing our Content-Type. Defends against MIME-confusion attacks.</description></item>
///   <item><description><c>X-Frame-Options: DENY</c>: refuses iframe embedding. Defends against clickjacking — attacker can't overlay an invisible auth-service iframe over their fake button.</description></item>
///   <item><description><c>Referrer-Policy</c>: caps what gets sent in the <c>Referer</c> header on outbound requests. Stops us leaking URLs (which contain reset-password tokens!) to third-party sites.</description></item>
///   <item><description><c>Permissions-Policy</c>: disables browser features the auth service has no business using (camera, microphone, geolocation). Defence in depth — if XSS ever did happen, the injected JS still couldn't access the camera.</description></item>
/// </list>
///
/// <para>HSTS is set separately via <c>app.UseHsts()</c> in
/// <c>WebApplicationExtensions.ConfigureApplicationAsync</c> (only in non-Development).</para>
/// </summary>
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        // CSP: minimum-viable policy that still lets our Razor pages run. The pages
        // include inline JavaScript, so 'self' + 'unsafe-inline' is required for scripts.
        headers.ContentSecurityPolicy =
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "form-action 'self'; " +
            "base-uri 'self'";

        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

        // Permissions-Policy: empty allow-lists for features the auth service never needs.
        //  says "no origin (including ours) is allowed to use this feature."
        headers["Permissions-Policy"] =
            "camera=(), " +
            "microphone=(), " +
            "geolocation=(), " +
            "payment=(), " +
            "usb=(), " +
            "fullscreen=()";

        await _next(context);
    }
}
