using AuthenticationService.Controllers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// <para><see cref="TestController"/> exists to demonstrate authorisation scenarios — the
/// admin-only endpoint and the any-authenticated-user endpoint. Both action methods are
/// trivial; the actual gate (<c>[Authorize(Policy = AdminOnly)]</c> / <c>[Authorize]</c>)
/// is enforced by ASP.NET Core's authorisation middleware, which we don't unit-test here
/// (it has its own test coverage upstream).</para>
///
/// <para>Tests pin the action returns OK with the expected payload when invoked directly
/// — sufficient to catch a refactor that accidentally changes the body or status code.</para>
/// </summary>
public class TestControllerTests
{
    [Fact]
    public void TestAdminOnly_ReturnsOkWithExpectedBody()
    {
        // arrange
        var controller = new TestController();

        // act
        var result = controller.TestAdminOnlyAsync();

        // assert
        result.Should().BeOfType<OkObjectResult>().Which.Value.Should().Be("Test succeeded");
    }

    [Fact]
    public void TestAllAuthenticatedUsers_ReturnsOkWithExpectedBody()
    {
        // arrange
        var controller = new TestController();

        // act
        var result = controller.TestAllAuthenticatedUsersAsync();

        // assert
        result.Should().BeOfType<OkObjectResult>().Which.Value.Should().Be("Test succeeded");
    }
}
