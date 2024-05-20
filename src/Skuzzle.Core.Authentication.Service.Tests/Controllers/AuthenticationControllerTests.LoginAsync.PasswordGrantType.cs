using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Moq;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Lib.ResultClass;
using System.Linq.Expressions;
using System.Net;

namespace Skuzzle.Core.Authentication.Service.Tests.Controllers;

public partial class AuthenticationControllerTests
{
    [Fact]
    public async Task LoginAsync_FormCollectionNotValidAuthenticationRequest_ReturnsBadRequest()
    {
        // arrange
        var formCollection = new FormCollection(
                new Dictionary<string, StringValues>()
                {
                    { "aKey", "aValue" },
                    { "bKey", "bValue" }
                });


        // act
        var result = await _sut.LoginAsync(formCollection);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<BadRequestObjectResult>();
    }

    // TODO: Plan to change this test if other grant_types are handled correctly by the LoginAsync method /nb
    [Fact]
    public async Task LoginAsync_UnhandledValidGrantType_ReturnsUnauthorized()
    {
        // arrange
        var formCollection = new FormCollection(
                new Dictionary<string, StringValues>()
                {
                    { "grant_type", "Implicit" },
                    { "username", "aValidUsername" },
                    { "password", "S0meTotallyValidPa55w0r&" }
                });


        // act
        var result = await _sut.LoginAsync(formCollection);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<UnauthorizedResult>();
    }

    [Fact]
    public async Task LoginAsync_PasswordGrantTypeUserRepoFails_ReturnsInternalServerError()
    {
        // arrange
        _userRepositoryMock
            .Setup(o => o.FirstOrDefaultAsync(It.IsAny<Expression<Func<User, bool>>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Fail<User>("Some error message"));

        // act
        var result = await _sut.LoginAsync(_passwordTypeFormCollection);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<ObjectResult>();
        
        var objectResult = result.Result as ObjectResult;
        objectResult!.StatusCode.Should().Be((int)HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task LoginAsync_PasswordGrantTypeUserNotFound_ReturnsUnauthorized()
    {
        // arrange
        _userRepositoryMock
            .Setup(o => o.FirstOrDefaultAsync(It.IsAny<Expression<Func<User, bool>>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok<User>(default));

        // act
        var result = await _sut.LoginAsync(_passwordTypeFormCollection);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task LoginAsync_PasswordGrantTypePasswordIncorrect_ReturnsUnauthorized()
    {
        // arrange
        _userRepositoryMock
            .Setup(o => o.FirstOrDefaultAsync(It.IsAny<Expression<Func<User, bool>>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok(_testUser));

        _passwordHashServiceMock
            .Setup(o => o.Verify(It.IsAny<AuthenticationRequest>(), It.IsAny<User>()))
            .Returns(false);

        // act
        var result = await _sut.LoginAsync(_passwordTypeFormCollection);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<UnauthorizedObjectResult>();
    }

    [Fact]
    public async Task LoginAsync_PasswordGrantTypePasswordCorrect_ReturnsOkWithNewToken()
    {
        // arrange
        var token = new Token(
            Guid.NewGuid(),
            "AccessToken",
            DateTimeOffset.UtcNow.AddMinutes(1),
            "RefreshToken",
            DateTimeOffset.UtcNow.AddMinutes(5));

        _userRepositoryMock
            .Setup(o => o.FirstOrDefaultAsync(It.IsAny<Expression<Func<User, bool>>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok(_testUser));

        _passwordHashServiceMock
            .Setup(o => o.Verify(It.IsAny<AuthenticationRequest>(), It.IsAny<User>()))
            .Returns(true);

        _tokenServiceMock
            .Setup(o => o.GetNewToken(It.IsAny<User>()))
            .Returns(token);

        // act
        var result = await _sut.LoginAsync(_passwordTypeFormCollection);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<OkObjectResult>();
        
        var okObjectResult = result.Result as OkObjectResult;
        okObjectResult!.Value.Should().BeOfType<Token>();
        okObjectResult.Value.Should().Be(token);
    }
}