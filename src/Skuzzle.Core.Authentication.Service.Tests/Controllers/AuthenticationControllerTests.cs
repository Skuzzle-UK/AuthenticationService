using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Moq;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Controllers;
using Skuzzle.Core.Authentication.Service.Extensions;
using Skuzzle.Core.Authentication.Service.Services;
using Skuzzle.Core.Authentication.Service.Storage;
using System.Security.Claims;

namespace Skuzzle.Core.Authentication.Service.Tests.Controllers;

public partial class AuthenticationControllerTests
{
    private readonly Mock<IPasswordHashService> _passwordHashServiceMock = new();
    private readonly Mock<ITokenService> _tokenServiceMock = new();
    private readonly Mock<IRepository<User>> _userRepositoryMock = new();
    private readonly Mock<IValidator<UserDto>> _userValidatorMock = new();
    private readonly Mock<HttpRequest> _httpRequestMock = new();
    private readonly Mock<HttpContext> _httpContextMock = new();

    private readonly UserDto _validUserDto;
    private readonly User _testUser;
    private readonly FormCollection _passwordTypeFormCollection;
    private readonly FormCollection _refreshTokenTypeFormCollection;
    private readonly ClaimsIdentity _validClaimsIdentity;
    private readonly ClaimsPrincipal _claimsPrincipal;

    private AuthenticationController _sut;

    public AuthenticationControllerTests()
    {
        _validUserDto = new UserDto()
        {
            Username = "Test",
            Email = "test@testemail.com",
            Password = "testin3$p255w0RD"
        };

        _testUser = new User()
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

        _passwordTypeFormCollection = new FormCollection(
            new Dictionary<string, StringValues>()
            {
                { "grant_type", "password" },
                { "username", _validUserDto.Username },
                { "password", _validUserDto.Password }
            });

        _refreshTokenTypeFormCollection = new FormCollection(
            new Dictionary<string, StringValues>()
            {
                { "grant_type", "refresh_token" },
                { "username", _validUserDto.Username },
                { "password", _validUserDto.Password },
                { "refresh_token", "a refresh token" }
            });

        _userValidatorMock
            .Setup(o => o.ValidateAsync(It.IsAny<UserDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _httpRequestMock
            .SetupGet(o => o.Headers)
            .Returns(
                new HeaderDictionary
                {
                    { "Authorization", "Bearer eyJhbGciO" }
                });

        _httpContextMock
            .SetupGet(o => o.Request)
            .Returns(_httpRequestMock.Object);

        _validClaimsIdentity = new ClaimsIdentity(
        new List<Claim>()
        {
            new Claim("UserId", Guid.NewGuid().ToString())
        });

        _claimsPrincipal = new ClaimsPrincipal(_validClaimsIdentity);

        _tokenServiceMock
            .Setup(o => o.ValidateToken(It.IsAny<string>(), It.IsAny<bool>()))
            .Returns(_claimsPrincipal);

        _sut = new AuthenticationController(
            _passwordHashServiceMock.Object,
            _tokenServiceMock.Object,
            _userRepositoryMock.Object,
            _userValidatorMock.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = _httpContextMock.Object
            }
        };
    }
}