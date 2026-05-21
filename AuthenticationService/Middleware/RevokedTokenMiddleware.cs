using AuthenticationService.Entities;
using AuthenticationService.Extensions;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

namespace AuthenticationService.Middleware;

/// <summary>
/// Rejects access tokens that were valid when issued but have since been revoked
/// (logout, password change, refresh-token theft, etc.). Adds a deny-list check on top
/// of JwtBearer's signature/expiry check. Replays are recorded for SIEM.
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
        var authorizationHeader = context.Request.Headers[HeaderNames.Authorization].ToString();

        // Non-Bearer schemes (Basic on /oauth/token, RFC 6749 §2.3.1) carry no JWT.
        // Trying to ReadJwtToken on them throws and 500s the request.
        if (!authorizationHeader.StartsWith(AuthSchemeConstants.BearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        var token = authorizationHeader[AuthSchemeConstants.BearerPrefix.Length..];
        if (string.IsNullOrEmpty(token))
        {
            // "Bearer " with nothing after — JwtBearer will issue the actual 401. Skip.
            await _next(context);
            return;
        }

        using (var scope = _serviceScopeFactory.CreateScope())
        {
            var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();

            RevokedToken? revokedToken;
            try
            {
                revokedToken = await tokenService.GetRevokedTokenAsync(token);
            }
            catch (Exception ex) when (ex is SecurityTokenMalformedException or UnauthorizedAccessException)
            {
                // Malformed JWT under "Bearer " — let JwtBearer handle the 401, skip the
                // deny-list lookup rather than 500.
                var logger = scope.ServiceProvider.GetService<ILogger<RevokedTokenMiddleware>>();
                logger?.LogWarning(
                    "Authorization header carried 'Bearer' prefix but the value is not a parseable JWT — passing through to JwtBearer. ({ExceptionType})",
                    ex.GetType().Name);
                await _next(context);
                return;
            }

            if (revokedToken is not null)
            {
                var userAgent = context.Request.Headers.UserAgent.ToString();
                await tokenService.RecordRevokedReplayAsync(revokedToken, context.GetRemoteIpAddress(), userAgent);

                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Token has been revoked");
                return;
            }
        }
        await _next(context);
    }
}
