using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Services;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IEmailService _emailService;
    private readonly ITokenService _tokenService;
    private readonly IUserService _userService;

    public AuthenticationController(
        IEmailService emailService,
        ITokenService tokenService,
        IUserService userService)
    {
        _emailService = emailService;
        _tokenService = tokenService;
        _userService = userService;
    }

    /// <summary>
    /// Endpoint for users to authenticate. This is the login endpoint which returns a token if not using 2FA or triggers a 2FA process.
    /// </summary>
    /// <param name="request">AuthenticationDto type</param>
    /// <returns>AuthenticationResult with token if not using 2FA or 2FA method used if using 2FA</returns>
    [HttpPost("authenticate")]
    public async Task<IActionResult> AuthenticateAsync([FromBody] AuthenticationDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, "Invalid request"));
        }

        if (!await _userService.IsEmailConfirmedAsync(user))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Email is not confirmed"));
        }

        if (await _userService.IsLockedOutAsync(user))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Your account is locked due to too many failed login attempts"));
        }

        if (!await _userService.CheckPasswordAsync(user, request.Password!))
        {
            return await RecordLoginFailedAttempt(user);
        }

        if (await _userService.GetTwoFactorEnabledAsync(user))
        {
            if (request.MfaProvider is null)
            {
                request.MfaProvider = user.Preferred2FAProvider;
            }

            var providers = await _userService.GetValidTwoFactorProvidersAsync(user);
            if (!providers.Contains(request.MfaProvider.ToString()!))
            {
                return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Invalid MFA Provider"));
            }

            switch (request.MfaProvider)
            {
                case MfaProviders.Email:
                    var mfaToken = await _userService.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
                    await _emailService.SendEmailAsync(
                        user.Email!,
                        "MFA Authentication Token",
                        $"Your token is: {mfaToken}");
                    break;
                case MfaProviders.Phone:
                    return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, "Phone MFA is not supported yet."));
                case MfaProviders.Authenticator:
                    break;
            }

            user.WaitingForTwoFactorAuthentication = true;
            await _userService.UpdateAsync(user);

            return Ok(AuthenticationResponse.WithMfaRequired(request.MfaProvider));
        }

        var roles = await _userService.GetRolesAsync(user);
        var token = await _tokenService.CreateTokenAsync(user, roles);

        await _userService.ResetAccessFailedCountAsync(user);

        return Ok(AuthenticationResponse.WithToken(token));
    }

    /// <summary>
    /// Endpoint for users to authenticate using 2FA. This is the endpoint that should be called after the user has received the 2FA token.
    /// This is step 2 of the login process which follows the AuthenticateAsync method if 2FA is enabled for the user.
    /// </summary>
    /// <param name="request">MfaAuthenticationDto</param>
    /// <returns>AuthenticationResponse with valid token if successful</returns>
    [HttpPost("mfa")]
    public async Task<IActionResult> MfaAuthenticateAsync([FromBody] MfaAuthenticationDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, "Invalid Request"));
        }

        if (!user.WaitingForTwoFactorAuthentication)
        {
            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, "Invalid Request"));
        }

        if (await _userService.IsLockedOutAsync(user))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Your account is locked due to too many failed login attempts."));
        }

        if (!await _userService.VerifyTwoFactorTokenAsync(user, request.MfaProvider.ToString()!, request.Token!))
        {
            return await RecordLoginFailedAttempt(user);
        }

        var roles = await _userService.GetRolesAsync(user);
        var token = await _tokenService.CreateTokenAsync(user, roles);

        await _userService.ResetAccessFailedCountAsync(user);

        user.WaitingForTwoFactorAuthentication = false;
        await _userService.UpdateAsync(user);

        return Ok(AuthenticationResponse.WithToken(token));
    }

    /// <summary>
    /// Refresh token endpoint. Requires bearer token in header as it checks the token claims
    /// </summary>
    /// <param name="request">RefreshTokenDto</param>
    /// <returns>AuthenticationResponse with valid token if successful</returns>
    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshTokenAsync([FromBody] RefreshTokenDto request)
    {
        var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        if (!await _tokenService.ValidateExpiredTokenAsync(token))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Token is invalid"));
        }

        var user = await _userService.FindByNameAsync(_tokenService.GetUserName(token));
        if (user is null)
        {
            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, "Invalid Request"));
        }

        if (user.RefreshToken != request.RefreshToken)
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Refresh token is invalid"));
        }

        if (user.RefreshTokenExpiresAt < DateTime.UtcNow)
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Refresh token has expired"));
        }

        var roles = await _userService.GetRolesAsync(user);
        var newToken = await _tokenService.CreateTokenAsync(user, roles);

        return Ok(AuthenticationResponse.WithToken(newToken));
    }

    /// <summary>
    /// Endpoint to log the user out. Invalidates the user's tokens and logs them out.
    /// </summary>
    /// <returns>ApiResponse</returns>
    [HttpGet("logout")]
    public async Task<IActionResult> LogoutAsync()
    {
        var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", string.Empty);

        var user = await _userService.FindByNameAsync(_tokenService.GetUserName(token));
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, "Invalid Request"));
        }

        await _userService.InvalidateUserTokensAsync(user, Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty, token);
        return Ok(new ApiResponse());
    }

    private async Task<IActionResult> RecordLoginFailedAttempt(User user)
    {
        await _userService.AccessFailedAsync(user);
        if (await _userService.IsLockedOutAsync(user))
        {
            var content = $"Your account is locked due to too many failed login attempts.";

            await _emailService.SendEmailAsync(
                user.Email!,
                "Locked account information",
                content);

            user.WaitingForTwoFactorAuthentication = false;
            await _userService.UpdateAsync(user);

            await _userService.InvalidateUserTokensAsync(user, Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty);

            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, content));
        }

        return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Authentication failed."));
    }
}
