using AuthenticationService.Extensions;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using Microsoft.Net.Http.Headers;

namespace AuthenticationService.Middleware;

/// <summary>
/// Rejects access tokens that were valid when issued but have since been revoked
/// (logout, password change, refresh-token theft, etc.). Sits between JwtBearer's
/// signature/expiry check and the controller — JwtBearer says "this token is properly
/// signed and not expired", we add "...and we haven't blacklisted it." Replays of
/// revoked tokens are recorded for SIEM forwarding.
/// </summary>
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
            var token = context.Request.Headers[HeaderNames.Authorization].ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);

            if (!string.IsNullOrEmpty(token))
            {
                var revokedToken = await tokenService.GetRevokedTokenAsync(token);
                if (revokedToken is not null)
                {
                    await tokenService.RecordRevokedReplayAsync(revokedToken, context.GetRemoteIpAddress());

                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("Token has been revoked");
                    return;
                }
            }
        }
        await _next(context);
    }
}
