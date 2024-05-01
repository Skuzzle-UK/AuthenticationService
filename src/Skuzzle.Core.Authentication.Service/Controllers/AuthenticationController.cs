using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Extensions;
using Skuzzle.Core.Authentication.Service.Services;
using Skuzzle.Core.Authentication.Service.Storage;
using System.Net;

namespace Skuzzle.Core.Authentication.Service.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IPasswordHashService _passwordHashService;
    private readonly ITokenService _tokenService;
    private readonly IRepository<User> _userRepository;
    private readonly IValidator<UserDto> _userValidator;
    
    public AuthenticationController(
        IPasswordHashService passwordHashService,
        ITokenService tokenService,
        IRepository<User> userRepository,
        IValidator<UserDto> userValidator)
    {
        _passwordHashService = passwordHashService;
        _tokenService = tokenService;
        _userRepository = userRepository;
        _userValidator = userValidator;
    }

    [HttpPost("register")]
    public async Task<ActionResult<string>> RegisterAsync(UserDto request)
    {
        var validationResults = await _userValidator.ValidateAsync(request);
        if (!validationResults.IsValid)
        {
            return BadRequest(validationResults);
        }

        var (hash, salt) = _passwordHashService.Create(request.Password);

        var user = new User()
        {
            Username = request.Username,
            Hash = hash,
            Salt = salt,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            Phone = request.Phone,
            Country = request.Country
        };

        var result = await _userRepository.InsertAsync(user);
        if (result.IsFailure)
        {
            return StatusCode((int)HttpStatusCode.InternalServerError, result.ErrorMessage);
        }

        return Ok();
    }

    [HttpPost("login")]
    public async Task<ActionResult<Token>> LoginAsync(UserCredentialsDto request)
    {
        var result = await _userRepository.FindAsync(o => o.Username == request.Username);
        if (result.IsFailure)
        {
            return StatusCode((int)HttpStatusCode.InternalServerError, result.ErrorMessage);
        }

        if (result.Value is null || result.Value.Username != request.Username)
        {
            return BadRequest("Incorrect login details");
        }

        if (!_passwordHashService.Verify(request, result.Value))
        {
            return BadRequest("Incorrect login details");
        }

        return Ok(_tokenService.GetNewToken(result.Value) ?? null);
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<Token>> RefreshAsync(Token token)
    {
        // TODO: Complete this once TokenService.cs has completed method/nb
        return Ok(token);
    }
}