using System.Net;
using AuthenticationService.Extensions;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;

namespace AuthenticationService.Tests.Extensions;

/// <summary>
/// <para>The IP-address extensions are called from controllers and middleware and feed
/// directly into SIEM payloads as the <c>{IpAddress}</c> field. Three paths exist: a real
/// IP is set, the IP is null (Kestrel test scenarios / behind certain proxies), and there's
/// no <see cref="HttpContext"/> at all (defensive).</para>
/// </summary>
public class HttpRequestExtensionsTests
{
    [Fact]
    public void GetRemoteIpAddress_OnHttpContext_RemoteIpSet_ReturnsStringRepresentation()
    {
        // arrange — typical incoming request: Kestrel surfaces RemoteIpAddress as IPv4 / IPv6.
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.42");

        // act
        var ip = context.GetRemoteIpAddress();

        // assert
        ip.Should().Be("203.0.113.42");
    }

    [Fact]
    public void GetRemoteIpAddress_OnHttpContext_RemoteIpNull_ReturnsEmptyString()
    {
        // arrange — Kestrel test host can leave Connection.RemoteIpAddress null. The
        // controller writes the result into a SIEM payload — null would crash; empty string
        // is the documented placeholder.
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = null;

        // act
        var ip = context.GetRemoteIpAddress();

        // assert
        ip.Should().Be(string.Empty);
    }

    [Fact]
    public void GetRemoteIpAddress_OnHttpRequest_DelegatesToHttpContextOverload()
    {
        // arrange — same scenario, but called through the Request overload (controllers
        // typically use this form).
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");

        // act
        var ip = context.Request.GetRemoteIpAddress();

        // assert — must agree with the HttpContext overload.
        ip.Should().Be("198.51.100.7");
        ip.Should().Be(context.GetRemoteIpAddress());
    }

    [Fact]
    public void GetRemoteIpAddress_IPv6_ReturnsBracketlessForm()
    {
        // arrange — IPv6 addresses get serialized without bracket-wrapping by ToString().
        // Pinned because the audit-log readers expect the same shape across IPv4 and IPv6.
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("2001:db8::1");

        // act
        var ip = context.GetRemoteIpAddress();

        // assert
        ip.Should().Be("2001:db8::1");
    }
}
