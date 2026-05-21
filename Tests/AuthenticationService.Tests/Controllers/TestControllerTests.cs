using AuthenticationService.Controllers;
using AwesomeAssertions;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Tests.Controllers;

/// <summary>
/// <see cref="TestController"/> demonstrates authorisation scenarios — the actual auth gate
/// is enforced by middleware (not tested here). Pins the body + status code only.
/// </summary>
public class TestControllerTests
{
    [Fact]
    public void TestAdminOnly_ReturnsOkWithExpectedBody()
    {
        var controller = new TestController();

        var result = controller.TestAdminOnlyAsync();

        result.Should().BeOfType<OkObjectResult>().Which.Value.Should().Be("Test succeeded");
    }

    [Fact]
    public void TestAllAuthenticatedUsers_ReturnsOkWithExpectedBody()
    {
        var controller = new TestController();

        var result = controller.TestAllAuthenticatedUsersAsync();

        result.Should().BeOfType<OkObjectResult>().Which.Value.Should().Be("Test succeeded");
    }
}
