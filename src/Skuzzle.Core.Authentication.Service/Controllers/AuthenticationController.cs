using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Enums;
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
            Country = request.Country,
        };

        // TODO: Look at putting possible roles into a database collection /nb
        user.Roles.Add("Unconfirmed User");

        var result = await _userRepository.CreateAsync(user);
        if (result.IsFailure)
        {
            return StatusCode((int)HttpStatusCode.InternalServerError, result.ErrorMessage);
        }

        return Ok();
    }

    [HttpPost("token")]
    public async Task<ActionResult<Token>> LoginAsync(IFormCollection formCollection)
    {
        var request = formCollection.ToAuthenticationRequest();
        if (request is null)
        {
            return BadRequest("Request form data does not match OAuth API standard.");
        }

        return request.GrantType switch
        {
            GrantType.Password => await PasswordGrantType(request),
            GrantType.Refresh_token => await RefreshTokenGrantType(request),
            _ => (ActionResult<Token>)Unauthorized(),
        };
    }

    private async Task<ActionResult<Token>> RefreshTokenGrantType(AuthenticationRequest request)
    {
        var token = Request.Headers.Authorization;
        if (token.IsNullOrEmptyOrWhiteSpace())
        {
            return Unauthorized();
        }

        var jwt = token.FirstOrDefault()!.Replace("Bearer ", "");

        var claimResult = _tokenService.ValidateToken(jwt, false);
        if (claimResult.IsFailure || claimResult.Value is null)
        {
            return Unauthorized();
        }

        var claim = claimResult.Value.FindFirst("UserId");
        if (claim is null || !Guid.TryParse(claim.Value, out var userId))
        {
            return Unauthorized();
        }

        var result = await _userRepository.FindAsync(userId);
        if (result.IsFailure)
        {
            return StatusCode((int)HttpStatusCode.InternalServerError, result.ErrorMessage);
        }

        if (result.Value is null || string.IsNullOrEmpty(request.RefreshToken))
        {
            return Unauthorized();
        }

        var newToken = _tokenService.RefreshToken(result.Value, request.RefreshToken);
        if (newToken is null)
        {
            return Unauthorized();
        }

        return Ok(newToken);
    }

    private async Task<ActionResult<Token>> PasswordGrantType(AuthenticationRequest request)
    {
        var result = await _userRepository.FirstOrDefaultAsync(o => o.Username == request.Username);
        if (result.IsFailure)
        {
            return StatusCode((int)HttpStatusCode.InternalServerError, result.ErrorMessage);
        }

        if (result.Value is null || result.Value.Username != request.Username || request.Password is null)
        {
            return Unauthorized("Incorrect login details");
        }

        var user = result.Value;

        if (!_passwordHashService.Verify(request.Password, user.Hash, user.Salt))
        {
            return Unauthorized("Incorrect login details");
        }

        return Ok(_tokenService.GetNewToken(result.Value) ?? null);
    }
}