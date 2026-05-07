using AuthenticationService.Entities;
using AuthenticationService.Middleware;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace AuthenticationService.Tests.Middleware;

/// <summary>
/// <para>The middleware sits between JwtBearer and the controllers and acts as the deny-list
/// gate for revoked tokens. Four paths exist:</para>
/// <list type="bullet">
///   <item><description>No Authorization header → pass through to next (JwtBearer already handled the auth challenge).</description></item>
///   <item><description>Bearer token present + token revoked → record replay, write 401 + body, short-circuit.</description></item>
///   <item><description>Bearer token present + token not revoked → pass through to next.</description></item>
///   <item><description>Bearer token present that's empty after stripping prefix → treated as no token (pass through).</description></item>
/// </list>
/// <para>The middleware also has to dispose its DI scope on every request — verified by
/// asserting <c>RecordRevokedReplayAsync</c> is called with the IP and UA from the request.</para>
/// </summary>
public class RevokedTokenMiddlewareTests
{
    [Fact]
    public async Task NoAuthorizationHeader_PassesThroughToNext()
    {
        // arrange — anonymous endpoint hit (or a controller that allowed this through).
        // Middleware must not block it.
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        var context = new DefaultHttpContext();

        // act
        await middleware.InvokeAsync(context);

        // assert
        nextCalled().Should().BeTrue();
        await tokenService.DidNotReceive().GetRevokedTokenAsync(Arg.Any<string>());
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK,
            because: "default status — middleware never wrote a response.");
    }

    [Fact]
    public async Task BearerHeaderEmptyAfterStrip_PassesThroughToNext()
    {
        // arrange — header literally "Bearer " (just the prefix). After stripping the prefix
        // there's nothing left; middleware treats this as "no token" and skips the lookup.
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix;

        // act
        await middleware.InvokeAsync(context);

        // assert
        nextCalled().Should().BeTrue();
        await tokenService.DidNotReceive().GetRevokedTokenAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task NotRevokedToken_PassesThroughToNext()
    {
        // arrange — happy path: token isn't on the deny-list.
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        tokenService.GetRevokedTokenAsync("eyJ.abc").Returns((RevokedToken?)null);
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix + "eyJ.abc";

        // act
        await middleware.InvokeAsync(context);

        // assert
        nextCalled().Should().BeTrue();
        await tokenService.Received(1).GetRevokedTokenAsync("eyJ.abc");
        await tokenService.DidNotReceive().RecordRevokedReplayAsync(
            Arg.Any<RevokedToken>(), Arg.Any<string>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task RevokedToken_ShortCircuitsWith401AndRecordsReplay()
    {
        // arrange — the gate path. Token is on the deny-list; middleware records the
        // attempt for SIEM, writes 401, returns without calling next.
        var (middleware, tokenService, nextCalled) = BuildMiddleware();
        var revoked = new RevokedToken { TokenJti = "j", UserId = "u" };
        tokenService.GetRevokedTokenAsync("eyJ.abc").Returns(revoked);

        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix + "eyJ.abc";
        context.Request.Headers.UserAgent = "TestAgent/1.0";
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.5");
        context.Response.Body = new MemoryStream();

        // act
        await middleware.InvokeAsync(context);

        // assert
        nextCalled().Should().BeFalse(because: "middleware short-circuits on revoked tokens — controller must not run.");
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        await tokenService.Received(1).RecordRevokedReplayAsync(revoked, "10.0.0.5", "TestAgent/1.0");
        ReadResponseBody(context).Should().Be("Token has been revoked");
    }

    [Fact]
    public async Task RevokedToken_NoUserAgentHeader_RecordsReplayWithEmptyAgent()
    {
        // arrange — UserAgent absent (machine-to-machine client). Middleware must still
        // record the attempt; UA is just a forensic field that may legitimately be blank.
        var (middleware, tokenService, _) = BuildMiddleware();
        var revoked = new RevokedToken { TokenJti = "j", UserId = "u" };
        tokenService.GetRevokedTokenAsync("eyJ.x").Returns(revoked);

        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix + "eyJ.x";
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.5");
        context.Response.Body = new MemoryStream();

        // act
        await middleware.InvokeAsync(context);

        // assert
        await tokenService.Received(1).RecordRevokedReplayAsync(revoked, "10.0.0.5", "");
    }

    [Fact]
    public async Task RevokedToken_NoRemoteIp_RecordsEmptyIpRatherThanThrow()
    {
        // arrange — Connection.RemoteIpAddress can be null in test scenarios / behind some
        // proxies. The IP is just a forensic field; middleware must record empty rather
        // than crash on the SIEM path.
        var (middleware, tokenService, _) = BuildMiddleware();
        var revoked = new RevokedToken { TokenJti = "j", UserId = "u" };
        tokenService.GetRevokedTokenAsync("eyJ.x").Returns(revoked);

        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = AuthSchemeConstants.BearerPrefix + "eyJ.x";
        context.Response.Body = new MemoryStream();

        // act
        var act = async () => await middleware.InvokeAsync(context);

        // assert
        await act.Should().NotThrowAsync();
        await tokenService.Received(1).RecordRevokedReplayAsync(revoked, "", Arg.Any<string?>());
    }

    private static (RevokedTokenMiddleware middleware, ITokenService tokenService, Func<bool> nextCalled) BuildMiddleware()
    {
        // arrange — wire up a real DI scope factory because the middleware uses
        // CreateScope() directly. We register a substituted ITokenService.
        var tokenService = Substitute.For<ITokenService>();
        var services = new ServiceCollection();
        services.AddScoped(_ => tokenService);
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
