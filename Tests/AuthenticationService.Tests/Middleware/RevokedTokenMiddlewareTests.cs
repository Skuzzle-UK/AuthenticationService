using AuthenticationService.Entities;
using AuthenticationService.Middleware;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace AuthenticationService.Tests.Middleware;

/// <summary>
/// Deny-list gate between JwtBearer and the controllers. Covers pass-through (no/non-Bearer/empty header),
/// short-circuit + replay record on revoked token, defensive pass-through on malformed JWT, and the IP/UA edge cases.
/// </summary>
public class RevokedTokenMiddlewareTests
{
    [Fact]
    public async Task NoAuthorizationHeader_PassesThroughToNext()
    {
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        var context = new DefaultHttpContext();

        await middleware.InvokeAsync(context);

        nextCalled().Should().BeTrue();
        await tokenService.DidNotReceive().GetRevokedTokenAsync(Arg.Any<string>());
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK,
            because: "default status — middleware never wrote a response.");
    }

    [Fact]
    public async Task BearerHeaderEmptyAfterStrip_PassesThroughToNext()
    {
        // Header literally "Bearer " — after stripping prefix nothing left; treat as no token.
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix;

        await middleware.InvokeAsync(context);

        nextCalled().Should().BeTrue();
        await tokenService.DidNotReceive().GetRevokedTokenAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task NotRevokedToken_PassesThroughToNext()
    {
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        tokenService.GetRevokedTokenAsync("eyJ.abc").Returns((RevokedToken?)null);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix + "eyJ.abc";

        await middleware.InvokeAsync(context);

        nextCalled().Should().BeTrue();
        await tokenService.Received(1).GetRevokedTokenAsync("eyJ.abc");
        await tokenService.DidNotReceive().RecordRevokedReplayAsync(
            Arg.Any<RevokedToken>(), Arg.Any<string>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task RevokedToken_ShortCircuitsWith401AndRecordsReplay()
    {
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        var revoked = new RevokedToken { TokenJti = "j", UserId = "u" };
        tokenService.GetRevokedTokenAsync("eyJ.abc").Returns(revoked);

        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix + "eyJ.abc";
        context.Request.Headers.UserAgent = "TestAgent/1.0";
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.5");
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context);

        nextCalled().Should().BeFalse(because: "middleware short-circuits on revoked tokens — controller must not run.");
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        await tokenService.Received(1).RecordRevokedReplayAsync(revoked, "10.0.0.5", "TestAgent/1.0");
        ReadResponseBody(context).Should().Be("Token has been revoked");
    }

    [Fact]
    public async Task RevokedToken_NoUserAgentHeader_RecordsReplayWithEmptyAgent()
    {
        var (middleware, tokenService, _) = BuildMiddleware();
        var revoked = new RevokedToken { TokenJti = "j", UserId = "u" };
        tokenService.GetRevokedTokenAsync("eyJ.x").Returns(revoked);

        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix + "eyJ.x";
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.5");
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context);

        await tokenService.Received(1).RecordRevokedReplayAsync(revoked, "10.0.0.5", "");
    }

    [Fact]
    public async Task NonBearerAuthorizationHeader_PassesThroughToNext_AndDoesNotJwtParse()
    {
        // /oauth/token uses Basic auth per RFC 6749 §2.3.1. Previously a blanket .Replace("Bearer ", "") left
        // the Basic header intact and 500'd on JwtSecurityTokenHandler — middleware now recognises non-Bearer schemes.
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ=";

        var act = async () => await middleware.InvokeAsync(context);

        await act.Should().NotThrowAsync(
            because: "Basic auth on /oauth/token is correct per RFC 6749; the middleware can't 500 on it.");
        nextCalled().Should().BeTrue();
        await tokenService.DidNotReceive().GetRevokedTokenAsync(Arg.Any<string>());
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK,
            because: "non-Bearer headers are not the middleware's concern; whatever handler authenticates them sets the eventual status.");
    }

    [Fact]
    public async Task BearerHeaderWithMalformedJwt_PassesThroughToNext_RatherThan500()
    {
        // "Bearer " followed by garbage previously caused ReadJwtToken to throw → 500. Middleware now catches and lets JwtBearer 401.
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        tokenService
            .GetRevokedTokenAsync("not-a-jwt")
            .Throws(new SecurityTokenMalformedException("IDX12709"));

        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix + "not-a-jwt";

        var act = async () => await middleware.InvokeAsync(context);

        await act.Should().NotThrowAsync();
        nextCalled().Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK,
            because: "a malformed JWT must not 500 — the auth pipeline rejects it cleanly via JwtBearer.");
    }

    [Fact]
    public async Task RevokedToken_NoRemoteIp_RecordsEmptyIpRatherThanThrow()
    {
        // RemoteIpAddress can be null in test scenarios / behind some proxies — record empty rather than crash.
        var (middleware, tokenService, _) = BuildMiddleware();
        var revoked = new RevokedToken { TokenJti = "j", UserId = "u" };
        tokenService.GetRevokedTokenAsync("eyJ.x").Returns(revoked);

        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix + "eyJ.x";
        context.Response.Body = new MemoryStream();

        var act = async () => await middleware.InvokeAsync(context);

        await act.Should().NotThrowAsync();
        await tokenService.Received(1).RecordRevokedReplayAsync(revoked, "", Arg.Any<string?>());
    }

    private static (RevokedTokenMiddleware middleware, ITokenService tokenService, Func<bool> nextCalled) BuildMiddleware()
    {
        // Real DI scope factory because middleware uses CreateScope() directly. Substituted ITokenService + a logging factory
        // (middleware resolves a logger from the per-request scope on the malformed-JWT defensive path).
        var tokenService = Substitute.For<ITokenService>();
        var services = new ServiceCollection();
        services.AddScoped(_ => tokenService);
        services.AddLogging();
        var sp = services.BuildServiceProvider();

        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };
        var middleware = new RevokedTokenMiddleware(next, sp.GetRequiredService<IServiceScopeFactory>());

        return (middleware, tokenService, () => nextCalled);
    }

    private static string ReadResponseBody(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body);
        return reader.ReadToEnd();
    }
}
