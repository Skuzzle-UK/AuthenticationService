using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Moq;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Controllers;
using Skuzzle.Core.Lib.ResultClass;
using System.Net;
using System.Security.Claims;

namespace Skuzzle.Core.Authentication.Service.Tests.Controllers;

public partial class AuthenticationControllerTests
{
    [Fact]
    public async Task LoginAsync_RefreshTokenGrantTypeAuthorizationHeaderIsEmpty_ReturnsUnauthorized()
    {
        // arrange
        _httpRequestMock
            .SetupGet(o => o.Headers)
            .Returns(
             new HeaderDictionary
             {
                { "Authorization", "" }
             });

        _httpContextMock
            .SetupGet(o => o.Request)
            .Returns(_httpRequestMock.Object);

        _sut = new AuthenticationController(
            _passwordHashServiceMock.Object,
            _tokenServiceMock.Object,
            _userServiceMock.Object,
            _userValidatorMock.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = _httpContextMock.Object
            }
        };

        // act
        var result = await _sut.LoginAsync(_refreshTokenTypeFormCollection, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<UnauthorizedResult>();
    }

    [Fact]
    public async Task LoginAsync_RefreshTokenGrantTypeUserIdClaimMissing_ReturnsInternalServerError()
    {
        // arrange
        _tokenServiceMock
            .Setup(o => o.ValidateToken(It.IsAny<string>(), It.IsAny<bool>()))
            .Returns(Result.Ok(new ClaimsPrincipal()));

        // act
        var result = await _sut.LoginAsync(_refreshTokenTypeFormCollection, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<UnauthorizedResult>();
    }

    [Fact]
    public async Task LoginAsync_RefreshTokenGrantTypeUserIdIsNotGuid_ReturnsUnauthorized()
    {
        // arrange
        var invalidClaimsIdentity = new ClaimsIdentity(
            new List<Claim>()
            {
                new Claim("UserId", "notAGuid")
            });

        var invalidClaimsPrincipal = new ClaimsPrincipal(invalidClaimsIdentity);

        _tokenServiceMock
            .Setup(o => o.ValidateToken(It.IsAny<string>(), It.IsAny<bool>()))
            .Returns(Result.Ok(invalidClaimsPrincipal));

        // act
        var result = await _sut.LoginAsync(_refreshTokenTypeFormCollection, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<UnauthorizedResult>();
    }

    [Fact]
    public async Task LoginAsync_RefreshTokenGrantTypeUserRepositoryFails_ReturnsInternalServerError()
    {
        // arrange
        _userServiceMock
            .Setup(o => o.GetById(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Fail<User>("Exception message"));

        // act
        var result = await _sut.LoginAsync(_refreshTokenTypeFormCollection, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();

        result.Result.Should().BeOfType<ObjectResult>();
        var objectResult = result.Result as ObjectResult;

        objectResult!.StatusCode.Should().Be((int)HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task LoginAsync_RefreshTokenGrantTypeUserDoesNotExist_ReturnsUnauthorised()
    {
        // arrange
        _userServiceMock
            .Setup(o => o.GetById(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok<User>(default!));

        // act
        var result = await _sut.LoginAsync(_refreshTokenTypeFormCollection, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<UnauthorizedResult>();
    }

    [Fact]
    public async Task LoginAsync_RefreshTokenGrantTypeRefreshTokenIsNullOrEmpty_ReturnsUnauthorised()
    {
        // arrange
        var refreshTokenMissingFormCollection = new FormCollection(
            new Dictionary<string, StringValues>()
            {
                { "grant_type", "refresh_token" },
                { "username", _validUserDto.Username },
                { "password", _validUserDto.Password }
            });

        _userServiceMock
            .Setup(o => o.GetById(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok(_testUser));

        // act
        var result = await _sut.LoginAsync(refreshTokenMissingFormCollection, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<UnauthorizedResult>();
    }

    [Fact]
    public async Task LoginAsync_RefreshTokenGrantTypeTokenServiceReturnsNull_ReturnsUnauthorised()
    {
        // arrange
        _userServiceMock
            .Setup(o => o.GetById(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok(_testUser));

        Token? token = null;

        _tokenServiceMock
            .Setup(o => o.RefreshToken(It.IsAny<User>(), It.IsAny<string>()))
            .Returns(token);

        // act
        var result = await _sut.LoginAsync(_refreshTokenTypeFormCollection, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<UnauthorizedResult>();
    }

    [Fact]
    public async Task LoginAsync_RefreshTokenGrantTypeFullyAuthorized_ReturnsToken()
    {
        // arrange
        _userServiceMock
            .Setup(o => o.GetById(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok(_testUser));

        var token = new Token(
            Guid.NewGuid(),
            "AccessToken",
            DateTimeOffset.UtcNow.AddMinutes(1),
            "RefreshToken",
            DateTimeOffset.UtcNow.AddMinutes(5));

        _tokenServiceMock
            .Setup(o => o.RefreshToken(It.IsAny<User>(), It.IsAny<string>()))
            .Returns(token);

        // act
        var result = await _sut.LoginAsync(_refreshTokenTypeFormCollection, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<Token>>();
        result.Result.Should().BeOfType<OkObjectResult>();

        var okObjectResult = result.Result as OkObjectResult;
        okObjectResult!.Value.Should().BeOfType<Token>();
        okObjectResult.Value.Should().Be(token);
    }
}