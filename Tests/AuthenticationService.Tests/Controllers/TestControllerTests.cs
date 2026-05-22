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
