using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Enums;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Extensions;
using Skuzzle.Core.Authentication.Service.Services.Interfaces;
using System.Net;

namespace Skuzzle.Core.Authentication.Service.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IPasswordHashService _passwordHashService;
    private readonly ITokenService _tokenService;
    private readonly IUserService _userService;
    private readonly IValidator<UserDto> _userValidator;

    public AuthenticationController(
        IPasswordHashService passwordHashService,
        ITokenService tokenService,
        IUserService userService,
        IValidator<UserDto> userValidator)
    {
        _passwordHashService = passwordHashService;
        _tokenService = tokenService;
        _userService = userService;
        _userValidator = userValidator;
    }

    [HttpPost("register")]
    public async Task<ActionResult<string>> RegisterAsync(UserDto request, CancellationToken ct)
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

        // TODO: Handle User already exists /nb
        var result = await _userService.CreateAsync(user, ct);
        if (result.IsFailure)
        {
            return StatusCode((int)HttpStatusCode.InternalServerError, result.ErrorMessage);
        }

        return Ok();
    }

    [HttpPost("token")]
    public async Task<ActionResult<Token>> LoginAsync([FromForm]IFormCollection formCollection, CancellationToken ct)
    {
        var request = formCollection.ToAuthenticationRequest();
        if (request is null)
        {
            return BadRequest("Request form data does not match OAuth API standard.");
        }

        return request.GrantType switch
        {
            GrantType.Password => await PasswordGrantType(request, ct),
            GrantType.Refresh_token => await RefreshTokenGrantType(request, ct),
            _ => (ActionResult<Token>)Unauthorized(),
        };
    }

    private async Task<ActionResult<Token>> RefreshTokenGrantType(AuthenticationRequest request, CancellationToken ct)
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

        // TODO: Can we handle not exists differently to internal server error /nb
        var result = await _userService.GetById(userId, ct);
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

    private async Task<ActionResult<Token>> PasswordGrantType(AuthenticationRequest request, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return Unauthorized("Incorrect login details");
        }

        var result = await _userService.GetByUsername(request.Username, ct);
        if (result.IsFailure)
        {
            return StatusCode((int)HttpStatusCode.InternalServerError, result.ErrorMessage);
        }

        // User does not exist
        if (result.Value is null)
        {
            return Unauthorized("Incorrect login details");
        }

        var user = result.Value;

        if (!_passwordHashService.Verify(request.Password, user.Hash, user.Salt))
        {
            return Unauthorized("Incorrect login details");
        }

        return Ok(_tokenService.GetNewToken(result.Value));
    }
}