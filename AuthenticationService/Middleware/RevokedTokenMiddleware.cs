using AuthenticationService.Entities;
using AuthenticationService.Extensions;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

namespace AuthenticationService.Middleware;

/// <summary>
/// Rejects access tokens that were valid when issued but have since been revoked
/// (logout, password change, refresh-token theft, etc.). Sits between JwtBearer's
/// signature/expiry check and the controller — JwtBearer says "this token is properly
/// signed and not expired", we add "...and we haven't blacklisted it." Replays of
/// revoked tokens are recorded for SIEM forwarding.
///
/// <para>The middleware runs on every request (including anonymous endpoints like
/// <c>/oauth/token</c>), so it must defensively recognise non-Bearer Authorization
/// headers — <c>Basic</c> credentials on <c>/oauth/token</c>, in particular — and
/// skip them, rather than blindly trying to JWT-parse them.</para>
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

        // Only Bearer tokens are revocation candidates. Other schemes — Basic credentials
        // on /oauth/token per RFC 6749 §2.3.1, anything else in the future — are
        // authenticated by different machinery and carry no JWT to look up. Blindly
        // running ReadJwtToken over a Basic header would throw SecurityTokenMalformedException
        // and 500 the request.
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
                // The "Bearer" prefix was present but the rest isn't a well-formed JWT — a
                // bad client, fuzzer, or scanner. JwtBearer will reject it cleanly with 401;
                // we just skip the deny-list lookup rather than 500. Logged as warning so
                // operational dashboards still surface it without a stack trace.
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
