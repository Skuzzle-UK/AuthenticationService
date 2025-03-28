using AuthenticationService.Services;

namespace AuthenticationService.Middleware;

public class RevokedTokenMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ITokenService _tokenService;

    public RevokedTokenMiddleware(
        RequestDelegate next,
        ITokenService tokenService)
    {
        _next = next;
        _tokenService = tokenService;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", string.Empty);
        if (!string.IsNullOrEmpty(token) && await _tokenService.IsRevokedAsync(token))
        {
            // TODO: Look at whether this could be a problem if many users originate from the same IP address /nb
            var ipaddress = context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
            await _tokenService.AddAccessAttemptAsync(token, ipaddress);

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Token has been revoked");
            return;
        }
        await _next(context);
    }
}
