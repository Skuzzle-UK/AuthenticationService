namespace AuthenticationService.Extensions;

public static class HttpRequestExtensions
{
    /// <summary>
    /// Caller's remote IP as a string, or empty if unresolvable.
    /// </summary>
    public static string GetRemoteIpAddress(this HttpRequest request) =>
        request.HttpContext.GetRemoteIpAddress();

    /// <summary>
    /// Caller's remote IP as a string, or empty if unresolvable.
    /// </summary>
    public static string GetRemoteIpAddress(this HttpContext context) =>
        context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
}
