namespace AuthenticationService.Extensions;

public static class HttpRequestExtensions
{
    /// <summary>
    /// Returns the remote IP address of the caller as a string, or <see cref="string.Empty"/>
    /// if it can't be resolved. Wraps the verbose <c>Request.HttpContext.Connection.RemoteIpAddress?.ToString()</c>
    /// pattern that's repeated across controllers for audit fields.
    /// </summary>
    public static string GetRemoteIpAddress(this HttpRequest request) =>
        request.HttpContext.GetRemoteIpAddress();

    /// <summary>
    /// Same as the <see cref="HttpRequest"/> overload, for callers that hold an
    /// <see cref="HttpContext"/> directly (middleware, hosted services).
    /// </summary>
    public static string GetRemoteIpAddress(this HttpContext context) =>
        context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
}
