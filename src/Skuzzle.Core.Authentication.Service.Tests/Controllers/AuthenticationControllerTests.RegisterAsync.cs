using FluentAssertions;
using FluentValidation.Results;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Lib.ResultClass;
using System.Net;

namespace Skuzzle.Core.Authentication.Service.Tests.Controllers;

public partial class AuthenticationControllerTests
{
    [Fact]
    public async Task RegisterAsync_InvalidUserDto_BadRequestWithValidationResults()
    {
        // arrange
        var invalidUserDto = new UserDto()
        {
            Username = "Test",
            Email = "q21e",
            Password = "test"
        };

        var emailValidationFailure = new ValidationFailure(
            "Email",
            "Email address must be a valid email address");

        var passwordValidationFailure = new ValidationFailure(
            "Password",
            "Your password must contain at least one uppercase letter, one lowercase letter, one number and one special character and be at least 8 characters long");

        var validationFailures = new List<ValidationFailure>()
        {
            emailValidationFailure,
            passwordValidationFailure
        };

        _userValidatorMock
            .Setup(o => o.ValidateAsync(invalidUserDto, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        // act
        var result = await _sut.RegisterAsync(invalidUserDto, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<string>>();

        result.Result.Should().BeOfType<BadRequestObjectResult>();
        var badRequestObjectResult = result.Result as BadRequestObjectResult;
        
        badRequestObjectResult!.Value.Should().BeOfType<ValidationResult>();
        var validationResult = badRequestObjectResult.Value as ValidationResult;

        validationResult!.Errors.Count.Should().Be(2);
        validationResult!.Errors[0].PropertyName.Should().Be("Email");
        validationResult!.Errors[0].ErrorMessage.Should().Be("Email address must be a valid email address");
        validationResult!.Errors[1].PropertyName.Should().Be("Password");
        validationResult!.Errors[1].ErrorMessage.Should().Be("Your password must contain at least one uppercase letter, one lowercase letter, one number and one special character and be at least 8 characters long");
    }

    [Fact]
    public async Task RegisterAsync_CreateUserFails_ReturnsInternalServerError()
    {
        // arrange
        _userServiceMock
            .Setup(o => o.CreateAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Fail<User>("Exception message"));

        // act
        var result = await _sut.RegisterAsync(_validUserDto, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<string>>();

        result.Result.Should().BeOfType<ObjectResult>();
        var objectResult = result.Result as ObjectResult;

        objectResult!.StatusCode.Should().Be((int)HttpStatusCode.InternalServerError);
    }

    [Fact]
    public async Task RegisterAsync_RepoCreateUser_ExpectedUserInParameters()
    {
        // arrange
        _userServiceMock
            .Setup(o => o.CreateAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok());

        // act
        var result = await _sut.RegisterAsync(_validUserDto, CancellationToken.None);

        // assert
        _userServiceMock.Verify(o => o.CreateAsync(
            It.Is<User>(u =>
                u.Username == _testUser.Username &&
                u.Email == _testUser.Email &&
                u.FirstName == _testUser.FirstName &&
                u.LastName == _testUser.LastName &&
                u.Phone == _testUser.Phone &&
                u.Country == _testUser.Country &&
                u.Roles[0] == "Unconfirmed User" &&
                u.Roles.Count == 1),
            It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task RegisterAsync_RepoCreateUserSuccessful_ReturnsOk()
    {
        // arrange
        _userServiceMock
            .Setup(o => o.CreateAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok());

        // act
        var result = await _sut.RegisterAsync(_validUserDto, CancellationToken.None);

        // assert
        result.Should().BeOfType<ActionResult<string>>();
        result.Result.Should().BeOfType<OkResult>();
    }
}