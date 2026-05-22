using System.Net;
using AuthenticationService.Extensions;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;

namespace AuthenticationService.Tests.Extensions;

/// <summary>
/// IP-address extensions feed directly into SIEM payloads as the <c>{IpAddress}</c> field.
/// Three paths: real IP, null IP, no HttpContext.
/// </summary>
public class HttpRequestExtensionsTests
{
    [Fact]
    public void GetRemoteIpAddress_OnHttpContext_RemoteIpSet_ReturnsStringRepresentation()
    {
        // arrange
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
        // arrange — null would crash the SIEM payload write, empty string is the documented placeholder.
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
        // arrange
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");

        // act
        var ip = context.Request.GetRemoteIpAddress();

        // assert
        ip.Should().Be("198.51.100.7");
        ip.Should().Be(context.GetRemoteIpAddress());
    }

    [Fact]
    public void GetRemoteIpAddress_IPv6_ReturnsBracketlessForm()
    {
        // arrange — audit-log readers expect the same shape across IPv4 and IPv6.
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("2001:db8::1");

        // act
        var ip = context.GetRemoteIpAddress();

        // assert
        ip.Should().Be("2001:db8::1");
    }
}
