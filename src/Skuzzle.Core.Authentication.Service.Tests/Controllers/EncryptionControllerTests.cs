using FluentAssertions;
using Microsoft.AspNetCore.Mvc;
using Skuzzle.Core.Authentication.Service.Controllers;

namespace Skuzzle.Core.Authentication.Service.Tests.Controllers;

public class EncryptionControllerTests
{
    private readonly EncryptionController _sut;

    public EncryptionControllerTests()
    {
        _sut = new EncryptionController();
    }

    [Fact]

    public void GenerateKeyAndIv_ReturnsOkWithStringContainingKeyAndIv()
    {
        // arrange

        // act
        var result = _sut.GenerateKeyAndIv();

        // assert
        result.Should().BeOfType<ActionResult<string>>();
        result.Result.Should().BeOfType<OkObjectResult>();

        var okObjectResult = result.Result as OkObjectResult;
        okObjectResult!.Value.Should().BeOfType<string>();
        okObjectResult.Value.Should().NotBe(string.Empty);
    }
}
