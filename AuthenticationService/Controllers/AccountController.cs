using AuthenticationService.Helpers;
using AuthenticationService.Services;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace AuthenticationService.Controllers;

// TODO: Update user details controller /nb

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly IEmailService _emailService;
    private readonly ITokenService _tokenService;
    private readonly IUserService _userService;

    public AccountController(
        IEmailService emailService,
        ITokenService tokenService,
        IUserService userService)
    {
        _emailService = emailService;
        _tokenService = tokenService;
        _userService = userService;
    }

    /// <summary>
    /// Endpoint to enable 2FA for a user. This endpoint should be called after the user has logged in and is setting up 2FA for the first time.
    /// Requires a valid auth token to reach this endpoint which should be gained from the AuthenticateAsync endpoint.
    /// </summary>
    /// <param name="request">EnableMfaRequest</param>
    /// <returns>EnableMfaResponse which contains a valid QrCode if requesting to use authenticator app</returns>
    [HttpGet("enablemfa")]
    [Authorize]
    public async Task<IActionResult> EnableMfaAsync(EnableMfaRequest request)
    {
        var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        
        var user = await _userService.FindByNameAsync(_tokenService.GetUserName(token));
        if(user is null)
        {
            return BadRequest(new AuthenticationResponse().AddError("Invalid Request"));
        }

        var key = await _userService.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userService.ResetAuthenticatorKeyAsync(user);
            key = await _userService.GetAuthenticatorKeyAsync(user);
        }

        var providers = await _userService.GetValidTwoFactorProvidersAsync(user);
        if (!providers.Contains(request.Preferred2FAProvider.ToString()!))
        {
            return Unauthorized(new AuthenticationResponse().AddError("Invalid MFA Provider"));
        }

        var current2fAStatus = await _userService.GetTwoFactorEnabledAsync(user);

        await _userService.SetTwoFactorEnabledAsync(user, true);

        if (request.Preferred2FAProvider is not null)
        {
            user.Preferred2FAProvider = request.Preferred2FAProvider.Value;
            await _userService.UpdateAsync(user);
        }

        var response = new EnableMfaResponse();

        switch (user.Preferred2FAProvider)
        {
            case MfaProviders.Email:
                response = new EnableMfaResponse(MfaProviders.Email);
                break;
            case MfaProviders.Phone:
                await _userService.SetTwoFactorEnabledAsync(user, current2fAStatus);
                return BadRequest(new AuthenticationResponse().AddError("Phone MFA is not supported yet."));
            case MfaProviders.Authenticator:
                response = new EnableMfaResponse(
                    MfaProviders.Authenticator,
                    QrCodeHelpers.NewPng(user.Email!, key!));
                break;
        }

        return Ok(response);
    }

    /// <summary>
    /// Endpoint to initiate the forgot password process. Generates a password reset token and sends an email with the reset link.
    /// </summary>
    /// <param name="request">ForgotPasswordDto type</param>
    /// <returns>ApiResponse indicating the result of the operation</returns>
    [HttpPost("forgotpassword")]
    public async Task<IActionResult> ForgotPasswordAsync([FromBody] ForgotPasswordDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null || !await _userService.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        if (await _userService.IsLockedOutAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Your account is locked."));
        }

        var token = await _userService.GeneratePasswordResetTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        if (string.IsNullOrWhiteSpace(request.ResetPasswordUri))
        {
            request.ResetPasswordUri = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/ResetPassword";
        }

        var resetPasswordUri = AccountHelpers.GenerateResetPasswordUri(user.Email!, encodedToken, request.ResetPasswordUri);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Password Reset",
            $"To reset your password, please click the following link: {resetPasswordUri}. If you didn't make this request please contact a system administrator.");

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Endpoint to reset the user's password using the provided token when forgotten.
    /// </summary>
    /// <param name="request">ResetForgottenPasswordDto type</param>
    /// <returns>ApiResponse indicating the result of the operation</returns>
    [HttpPost("forgotpassword/reset")]
    public async Task<IActionResult> ResetForgottenPasswordAsync([FromBody] ResetForgottenPasswordDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null || !await _userService.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        if (await _userService.IsLockedOutAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Your account is locked."));
        }

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token!));

        var resetResult = await _userService.ResetPasswordAsync(user, decodedToken, request.NewPassword!);
        if (!resetResult.Succeeded)
        {
            var errors = resetResult.Errors.Select(e => e.Description);
            return BadRequest(new ApiResponse().AddErrors(errors));
        }

        await _userService.InvalidateUserTokensAsync(user, Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty);

        var lockoutToken = await _userService.GenerateUserTokenAsync(user, MfaProviders.Email.ToString(), "Lockout");

        if (string.IsNullOrWhiteSpace(request.LockAccountUri))
        {
            request.LockAccountUri = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/LockAccount";
        }

        var lockAccountUri = AccountHelpers.GenerateLockoutUri(user.Email!, lockoutToken, request.LockAccountUri);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Password Reset",
            $"Your password was reset at {DateTime.UtcNow} UTC. If you didn't make this request please click the following link to lock your account and contact a system administrator. {lockAccountUri}");

        user.LockoutEnd = null;
        await _userService.UpdateAsync(user);

        await _userService.ResetAccessFailedCountAsync(user);
        
        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Endpoint to change the user's password.
    /// </summary>
    /// <param name="request">ChangePasswordDto type</param>
    /// <returns>ApiResponse indicating the result of the operation</returns>
    [HttpPost("changepassword")]
    [Authorize]
    public async Task<IActionResult> ChangePasswordAsync([FromBody] ChangePasswordDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null || !await _userService.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        var resetResult = await _userService.ChangePasswordAsync(user, request.OldPassword!, request.NewPassword!);
        if (!resetResult.Succeeded)
        {
            var errors = resetResult.Errors.Select(e => e.Description);
            return BadRequest(new ApiResponse().AddErrors(errors));
        }

        var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        await _userService.InvalidateUserTokensAsync(user, Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty, token);

        var lockoutToken = await _userService.GenerateUserTokenAsync(user, MfaProviders.Email.ToString(), "Lockout");

        if (string.IsNullOrWhiteSpace(request.LockAccountUri))
        {
            request.LockAccountUri = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/LockAccount";
        }

        var lockAccountUri = AccountHelpers.GenerateLockoutUri(user.Email!, lockoutToken, request.LockAccountUri);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Password Reset",
            $"Your password was reset at {DateTime.UtcNow} UTC. If you didn't make this request please click the following link to lock your account and contact a system administrator. {lockAccountUri}");

        user.LockoutEnd = null;
        await _userService.UpdateAsync(user);

        await _userService.ResetAccessFailedCountAsync(user);
        
        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Enables user to follow email link to lock out an account if password was changed without user consent
    /// </summary>
    /// <param name="request">LockAccountDto</param>
    /// <returns>ApiResponse</returns>
    [HttpPost("lock")]
    public async Task<IActionResult> LockAccountAsync(LockAccountDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        if (!await _userService.VerifyUserTokenAsync(user, MfaProviders.Email.ToString(), "Lockout", request.Token!))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        await _userService.InvalidateUserTokensAsync(user, Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty);

        await _userService.SetLockoutEnabledAsync(user, true);
        await _userService.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddYears(100));

        if (string.IsNullOrWhiteSpace(request.RetrieveAccountUri))
        {
            request.RetrieveAccountUri = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/RetrieveAccount";
        }

        await _emailService.SendEmailAsync(
            user.Email!,
            "Account Locked",
            $"Your account was locked at {DateTime.UtcNow} UTC. If you didn't make this request please contact a system administrator. To unlock your account click the following link. {request.RetrieveAccountUri}");

        return Ok(new ApiResponse());
    }

    [HttpPost("retrieve")]
    public async Task<IActionResult> RetrieveAccountAsync(RetrieveAccountDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        if (!_userService.VerifyRetrieveAccountValues(
            user,
            request.UserName,
            request.FirstName,
            request.LastName,
            request.DateOfBirth,
            request.Email,
            request.PhoneNumber,
            request.Country,
            request.MothersMaidenName,
            request.AddressLine1,
            request.AddressLine2,
            request.AddressLine3,
            request.Postcode,
            request.City))
        {
            return Unauthorized(new AuthenticationResponse().AddError("One or more values are not correct."));
        }

        var resetToken = await _userService.GeneratePasswordResetTokenAsync(user);

        var resetResult = await _userService.ResetPasswordAsync(user, resetToken, request.NewPassword!);
        if (!resetResult.Succeeded)
        {
            var errors = resetResult.Errors.Select(e => e.Description);
            return BadRequest(new ApiResponse().AddErrors(errors));
        }

        await _userService.InvalidateUserTokensAsync(user, Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty);

        var lockoutToken = await _userService.GenerateUserTokenAsync(user, MfaProviders.Email.ToString(), "Lockout");

        if (string.IsNullOrWhiteSpace(request.LockAccountUri))
        {
            request.LockAccountUri = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/LockAccount";
        }

        await _userService.SetLockoutEndDateAsync(user, null);

        var lockAccountUri = AccountHelpers.GenerateLockoutUri(user.Email!, lockoutToken, request.LockAccountUri);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Account Retrieval Password Reset",
            $"Your account was unlocked and password was reset at {DateTime.UtcNow} UTC. If you didn't make this request please click the following link to lock your account and contact a system administrator. {lockAccountUri}");

        return Ok(new ApiResponse());
    }
}