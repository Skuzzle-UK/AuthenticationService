using AuthenticationService.Services;

namespace AuthenticationService.Middleware;

public class RevokedTokenMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IServiceScopeFactory _serviceScopeFactory;

    public RevokedTokenMiddleware(
        RequestDelegate next,
        IServiceScopeFactory serviceScopeFactory)
    {
        _next = next;
        _serviceScopeFactory = serviceScopeFactory;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        using (var scope = _serviceScopeFactory.CreateScope())
        {
            var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
            var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", string.Empty);
            if (!string.IsNullOrEmpty(token) && await tokenService.IsRevokedAsync(token))
            {
                var ipaddress = context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
                await tokenService.AddAccessAttemptAsync(token, ipaddress);

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Token has been revoked");
                return;
            }
        }
        await _next(context);
    }
}
