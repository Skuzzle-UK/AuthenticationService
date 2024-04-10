using Microsoft.AspNetCore.Mvc;
using Skuzzle.Core.Service.AuthenticationService.Dtos;
using Skuzzle.Core.Service.AuthenticationService.Extensions;
using Skuzzle.Core.Service.AuthenticationService.Models;
using Skuzzle.Core.Service.AuthenticationService.Services;
using Skuzzle.Core.Service.AuthenticationService.Storage;

namespace Skuzzle.Core.Service.AuthenticationService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IPasswordHashService _passwordHashService;
    private readonly ITokenService _tokenService;
    private readonly IRepository<User> _userRepository;
    
    public AuthenticationController(
        IPasswordHashService passwordHashService,
        ITokenService tokenService,
        IRepository<User> userRepository)
    {
        _passwordHashService = passwordHashService;
        _tokenService = tokenService;
        _userRepository = userRepository;
    }

    [HttpPost("register")]
    public async Task<ActionResult<string>> Register(UserDto request)
    {
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

        await _userRepository.InsertAsync(user);

        return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<string>> Login(UserCredentialsDto request)
    {
        var user = await _userRepository.FindAsync(o => o.Username == request.Username);

        if(user is null || user.Username != request.Username)
        {
            return BadRequest("User not found");
        }

        if(!_passwordHashService.Verify(request, user))
        {
            return BadRequest("Wrong password");
        }

        return Ok(_tokenService.GetNewToken(user) ?? string.Empty);
    }
}