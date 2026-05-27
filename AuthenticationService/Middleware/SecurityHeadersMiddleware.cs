namespace AuthenticationService.Middleware;

/// <summary>
/// Adds defence-in-depth security headers (CSP, nosniff, frame-deny, referrer-policy,
/// permissions-policy). Mostly hardens the Razor pages — API clients ignore them. HSTS
/// is set separately via <c>app.UseHsts()</c> in non-Development.
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

        // Razor pages load JS from external files under wwwroot/js/ and pass server-side
        // state via data-* attributes.
        headers.ContentSecurityPolicy =
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self'; " +
            "img-src 'self' data:; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "form-action 'self'; " +
            "base-uri 'self'";

        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

        // Empty allow-lists: no origin (including ours) may use the feature.
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
