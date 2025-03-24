using AuthenticationService.Dtos;
using AuthenticationService.Dtos.Response;
using AuthenticationService.Entities;
using AuthenticationService.JwtFeatures;
using AuthenticationService.Services;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Runtime.InteropServices;

namespace AuthenticationService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountsController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly IEmailService _emailService;
    private readonly IMapper _mapper;
    private readonly JwtHandler _jwtHandler;

    public AccountsController(
        UserManager<User> userManager,
        IEmailService emailService,
        IMapper mapper,
        JwtHandler jwtHandler)
    {
        _userManager = userManager;
        _emailService = emailService;
        _mapper = mapper;
        _jwtHandler = jwtHandler;
    }

    // TODO: Endpoint to resend email confirmation request /nb
    // TODO: Forgot/Reset password methods /nb
    // TODO: Ensure reset method has setlockoutenddate and set to null

    [HttpPost("register")]
    public async Task<IActionResult> RegisterUserAsync([FromBody] UserRegistrationDto userDto)
    {
        if (userDto is null)
        {
            return BadRequest();
        }

        var user = _mapper.Map<User>(userDto);
        var result = await _userManager.CreateAsync(user, userDto.Password!);
        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => e.Description);

            return BadRequest(new UserRegistrationResponse { Errors = errors });
        }

        await _userManager.SetTwoFactorEnabledAsync(user, userDto.EnableMfa ?? false);

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        var param = new Dictionary<string, string>
        {
            { "token", token },
            { "email", user.Email! }
        };

        var callback = QueryHelpers.AddQueryString(userDto.ClientUri!, param!);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Email Confirmation",
            $"To confirm your email address please click the following link: {callback}");

        await _userManager.AddToRoleAsync(user, "Visitor");

        return Created();
    }

    [HttpPost("authenticate")]
    public async Task<IActionResult> AuthenticateAsync([FromBody] UserAuthenticationDto authDto)
    {
        var user = await _userManager.FindByEmailAsync(authDto.Email!);
        if (user is null)
        {
            return BadRequest("Invalid Request");
        }

        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            return Unauthorized(new UserAuthenticationResponse { ErrorMessage = "Email is not confirmed" });
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return Unauthorized(new UserAuthenticationResponse { ErrorMessage = "The account is locked due to to many failed login attempts" });
        }

        if (!await _userManager.CheckPasswordAsync(user, authDto.Password!))
        {
            await _userManager.AccessFailedAsync(user);
            if (await _userManager.IsLockedOutAsync(user))
            {
                var content = $"Your account is locked out due to to many failed login attempts.";

                await _emailService.SendEmailAsync(
                    user.Email!,
                    "Locked account information",
                    "Your account is locked out due to to many failed login attempts.");

                return Unauthorized(new UserAuthenticationResponse { ErrorMessage = content });
            }    
            return Unauthorized(new UserAuthenticationResponse { ErrorMessage = "Invalid Authentication" });
        }

        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (!providers.Contains("Email"))
            {
                return Unauthorized(new UserAuthenticationResponse { ErrorMessage = "Invalid MFA Provider" });
            }

            var mfaToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

            await _emailService.SendEmailAsync(
                user.Email!,
                "MFA Authentication Token",
                $"Your token is: {mfaToken}");

            return Ok(new UserAuthenticationResponse { MfaRequired = true, Provider = "Email" });
        }

        var roles = await _userManager.GetRolesAsync(user);
        var token = _jwtHandler.CreateToken(user, roles);

        await _userManager.ResetAccessFailedCountAsync(user);

        return Ok(new UserAuthenticationResponse { IsSuccess = true, Token = token});
    }

    [HttpGet("confirm/email")]
    public async Task<IActionResult> ConfirmEmailAsync([FromQuery] string email, [FromQuery] string token)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null)
        {
            return BadRequest("Invalid email confirmation request");
        }

        var confirmationResult = await _userManager.ConfirmEmailAsync(user, token);
        if (!confirmationResult.Succeeded)
        {
            return BadRequest("Invalid email confirmation request");
        }

        return Ok();
    }

    [HttpPost("authenticate/mfa")]
    public async Task<IActionResult> MfaAuthenticationAsync([FromBody] MfaAuthenticationDto mfaDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest();
        }

        var user = await _userManager.FindByEmailAsync(mfaDto.Email!);
        if (user is null)
        {
            return BadRequest("Invalid Request");
        }

        try
        {
            var validToken = await _userManager.VerifyTwoFactorTokenAsync(user, mfaDto.Provider!, mfaDto.Token!);
        }
        catch
        {
            return BadRequest("Invalid Request");
        }

        var roles = await _userManager.GetRolesAsync(user);
        var token = _jwtHandler.CreateToken(user, roles);

        await _userManager.ResetAccessFailedCountAsync(user);

        return Ok(new UserAuthenticationResponse { IsSuccess = true, Token = token });
    }
}
