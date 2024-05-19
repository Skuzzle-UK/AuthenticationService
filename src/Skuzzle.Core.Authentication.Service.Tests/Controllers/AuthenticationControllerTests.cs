using FluentAssertions;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Controllers;
using Skuzzle.Core.Authentication.Service.Extensions;
using Skuzzle.Core.Authentication.Service.Services;
using Skuzzle.Core.Authentication.Service.Storage;
using Skuzzle.Core.Lib.ResultClass;
using System.Net;

namespace Skuzzle.Core.Authentication.Service.Tests.Controllers;

public class AuthenticationControllerTests
{
    private readonly Mock<IPasswordHashService> _passwordHashServiceMock = new();
    private readonly Mock<ITokenService> _tokenServiceMock = new();
    private readonly Mock<IRepository<User>> _userRepositoryMock = new();
    private readonly Mock<IValidator<UserDto>> _userValidatorMock = new();

    private readonly AuthenticationController _sut;

    private readonly UserDto _validUserDto;

    public AuthenticationControllerTests()
    {
        _validUserDto = new UserDto()
        {
            Username = "Test",
            Email = "test@testemail.com",
            Password = "testin3$p255w0RD"
        };

        _userValidatorMock
            .Setup(o => o.ValidateAsync(It.IsAny<UserDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _sut = new AuthenticationController(
            _passwordHashServiceMock.Object,
            _tokenServiceMock.Object,
            _userRepositoryMock.Object,
            _userValidatorMock.Object);
    }

    #region RegisterAsync Tests
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
        var result = await _sut.RegisterAsync(invalidUserDto);

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
        _userRepositoryMock
            .Setup(o => o.CreateAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Fail<User>("Exception message"));

        // act
        var result = await _sut.RegisterAsync(_validUserDto);

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
        var expectedUser = new User()
        {
            Username = _validUserDto.Username,
            Hash = default, // required value - not checked
            Salt = default, // required value - not checked
            Email = _validUserDto.Email,
            FirstName = _validUserDto.FirstName,
            LastName = _validUserDto.LastName,
            Country = _validUserDto.Country,
            Phone = _validUserDto.Phone
        };

        // act
        var result = await _sut.RegisterAsync(_validUserDto);

        // assert
        _userRepositoryMock.Verify(o => o.CreateAsync(
            It.Is<User>(u =>
                u.Username == expectedUser.Username &&
                u.Email == expectedUser.Email &&
                u.FirstName == expectedUser.FirstName &&
                u.LastName == expectedUser.LastName &&
                u.Phone == expectedUser.Phone &&
                u.Country == expectedUser.Country &&
                u.Roles[0] == expectedUser.Roles[0] &&
                u.Roles.Count == expectedUser.Roles.Count),
            It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task RegisterAsync_RepoCreateUserSuccessful_ReturnsOk()
    {
        // arrange
        _userRepositoryMock
            .Setup(o => o.CreateAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Ok());

        // act
        var result = await _sut.RegisterAsync(_validUserDto);

        // assert
        result.Should().BeOfType<ActionResult<string>>();
        result.Result.Should().BeOfType<OkResult>();
    }
    #endregion

    #region LoginAsync Tests
    // TODO: Create tests for LoginAsync /nb
    #endregion
}