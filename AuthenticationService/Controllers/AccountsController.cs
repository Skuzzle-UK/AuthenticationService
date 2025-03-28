using AuthenticationService.Entities;
using AuthenticationService.Helpers;
using AuthenticationService.Services;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using AuthenticationService.Storage;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthenticationService.Controllers;

// TODO: Build in account recovery solution for locked accounts /nb

[Route("api/[controller]")]
[ApiController]
public class AccountsController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly IEmailService _emailService;
    private readonly ITokenService _tokenService;
    private readonly IMapper _mapper;
    private readonly DatabaseContext _dbContext;

    public AccountsController(
        UserManager<User> userManager,
        IEmailService emailService,
        ITokenService tokenService,
        IMapper mapper,
        DatabaseContext dbContext)
    {
        _userManager = userManager;
        _emailService = emailService;
        _tokenService = tokenService;
        _mapper = mapper;
        _dbContext = dbContext;
    }

    /// <summary>
    /// Registration endpoint for new users. Step 1 of the registration process.
    /// </summary>
    /// <param name="request">Should be of type RegistrationDto</param>
    /// <returns>Created response if all has gone well</returns>
    [HttpPost("register")]
    public async Task<IActionResult> RegisterUserAsync([FromBody] RegistrationDto request)
    {
        if (request is null)
        {
            return BadRequest();
        }

        var user = _mapper.Map<User>(request);

        using var transaction = await _dbContext.Database.BeginTransactionAsync();

        try
        {
            var result = await _userManager.CreateAsync(user, request.Password!);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description);
                return BadRequest(new ApiResponse().AddErrors(errors));
            }

            if (request.Preferred2FAProvider is not null)
            {
                user.Preferred2FAProvider = request.Preferred2FAProvider.Value;
                await _userManager.UpdateAsync(user);
            }

            await _userManager.AddToRoleAsync(user, "User");

            await SendConfirmEmailAsync(user, request.EmailConfirmationCallbackUri);

            await transaction.CommitAsync();

            return Created();
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return StatusCode(500, ex.Message);
        }
    }

    /// <summary>
    /// Endpoint for users to confirm their email address. Step 2 of the registration process.
    /// Usually reached from email link sent in step 1.
    /// </summary>
    /// <param name="email">Requires valid email address</param>
    /// <param name="token">Token generated and sent to email in step 1</param>
    /// <param name="callbackUri">URI which user is redirected to after confirmation. Usually a page on the UI saying email confirmed and offering login</param>
    /// <returns>ApiResponse or redirects to callbackUri</returns>
    [HttpGet("confirm/email")]
    public async Task<IActionResult> ConfirmEmailAsync([FromQuery] string email, [FromQuery] string token, [FromQuery] string? callbackUri)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError("Invalid email confirmation request"));
        }

        var confirmationResult = await _userManager.ConfirmEmailAsync(user, token);
        if (!confirmationResult.Succeeded)
        {
            return BadRequest(new ApiResponse().AddError("Invalid email confirmation request"));
        }

        return string.IsNullOrWhiteSpace(callbackUri)
            ? Ok(new ApiResponse())
            : Redirect(callbackUri);
    }

    /// <summary>
    /// Resends the email confirmation email.
    /// </summary>
    /// <param name="request">ResendConfirmEmailAsync</param>
    /// <returns>ApiResponse</returns>
    [HttpPost("confirm/email")]
    public async Task<IActionResult> ResendConfirmEmailAsync([FromBody] ResendEmailConfirmationDto request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        if (await _userManager.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        await SendConfirmEmailAsync(user, request.CallbackUri);

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Endpoint for users to authenticate. This is the login endpoint which returns a token if not using 2FA or triggers a 2FA process.
    /// </summary>
    /// <param name="request">AuthenticationDto type</param>
    /// <returns>AuthenticationResult with token if not using 2FA or 2FA method used if using 2FA</returns>
    [HttpPost("authenticate")]
    public async Task<IActionResult> AuthenticateAsync([FromBody] AuthenticationDto request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new AuthenticationResponse().AddError("Invalid request"));
        }

        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            return Unauthorized(new AuthenticationResponse().AddError("Email is not confirmed"));
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return Unauthorized(new AuthenticationResponse().AddError("Your account is locked due to too many failed login attempts"));
        }

        if (!await _userManager.CheckPasswordAsync(user, request.Password!))
        {
            return await RecordLoginFailedAttempt(user);
        }

        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            if (request.MfaProvider is null)
            {
                request.MfaProvider = user.Preferred2FAProvider;
            }

            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            if (!providers.Contains(request.MfaProvider.ToString()!))
            {
                return Unauthorized(new AuthenticationResponse().AddError("Invalid MFA Provider"));
            }

            switch (request.MfaProvider)
            {
                case MfaProviders.Email:
                    var mfaToken = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
                    await _emailService.SendEmailAsync(
                        user.Email!,
                        "MFA Authentication Token",
                        $"Your token is: {mfaToken}");
                    break;
                case MfaProviders.Phone:
                    return BadRequest(new AuthenticationResponse().AddError("Phone MFA is not supported yet."));
                case MfaProviders.Authenticator:
                    break;
            }

            user.WaitingForTwoFactorAuthentication = true;
            await _userManager.UpdateAsync(user);

            return Ok(AuthenticationResponse.WithMfaRequired(request.MfaProvider));
        }

        var roles = await _userManager.GetRolesAsync(user);
        var token = await _tokenService.CreateTokenAsync(user, roles);

        await _userManager.ResetAccessFailedCountAsync(user);

        return Ok(AuthenticationResponse.WithToken(token));
    }

    /// <summary>
    /// Endpoint for users to authenticate using 2FA. This is the endpoint that should be called after the user has received the 2FA token.
    /// This is step 2 of the login process which follows the AuthenticateAsync method if 2FA is enabled for the user.
    /// </summary>
    /// <param name="request">MfaAuthenticationDto</param>
    /// <returns>AuthenticationResponse with valid token if successful</returns>
    [HttpPost("authenticate/mfa")]
    public async Task<IActionResult> MfaAuthenticateAsync([FromBody] MfaAuthenticationDto request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new AuthenticationResponse().AddError("Invalid Request"));
        }

        if (!user.WaitingForTwoFactorAuthentication)
        {
            return BadRequest(new AuthenticationResponse().AddError("Invalid Request"));
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return Unauthorized(new AuthenticationResponse().AddError("Your account is locked due to too many failed login attempts."));
        }

        if (!await _userManager.VerifyTwoFactorTokenAsync(user, request.MfaProvider.ToString()!, request.Token!))
        {
            return await RecordLoginFailedAttempt(user);
        }

        var roles = await _userManager.GetRolesAsync(user);
        var token = await _tokenService.CreateTokenAsync(user, roles);

        await _userManager.ResetAccessFailedCountAsync(user);

        user.WaitingForTwoFactorAuthentication = false;
        await _userManager.UpdateAsync(user);

        return Ok(AuthenticationResponse.WithToken(token));
    }

    /// <summary>
    /// Enpoint to enable 2FA for a user. This endpoint should be called after the user has logged in and is setting up 2FA for the first time.
    /// Requires a valid auth token to reach this endpoint which should be gained from the AuthenticateAsync endpoint.
    /// </summary>
    /// <param name="request">EnableMfaRequest</param>
    /// <returns>EnableMfaResponse which contains a valid QrCode if requesting to use authenticator app</returns>
    [HttpGet("enablemfa")]
    [Authorize]
    public async Task<IActionResult> EnableMfaAsync(EnableMfaRequest request)
    {
        var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        
        var user = await _userManager.FindByNameAsync(_tokenService.GetUserName(token));
        if(user is null)
        {
            return BadRequest(new AuthenticationResponse().AddError("Invalid Request"));
        }

        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
        if (!providers.Contains(request.Preferred2FAProvider.ToString()!))
        {
            return Unauthorized(new AuthenticationResponse().AddError("Invalid MFA Provider"));
        }

        var current2fAStatus = await _userManager.GetTwoFactorEnabledAsync(user);

        await _userManager.SetTwoFactorEnabledAsync(user, true);

        if (request.Preferred2FAProvider is not null)
        {
            user.Preferred2FAProvider = request.Preferred2FAProvider.Value;
            await _userManager.UpdateAsync(user);
        }

        var response = new EnableMfaResponse();

        switch (user.Preferred2FAProvider)
        {
            case MfaProviders.Email:
                response = new EnableMfaResponse(MfaProviders.Email);
                break;
            case MfaProviders.Phone:
                await _userManager.SetTwoFactorEnabledAsync(user, current2fAStatus);
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
    /// Refresh token endpoint. Requires bearer token in header as it checks the token claims
    /// </summary>
    /// <param name="request">RefreshTokenDto</param>
    /// <returns>AuthenticationResponse with valid token if successful</returns>
    [HttpPost("authenticate/refresh")]
    public async Task<IActionResult> RefreshTokenAsync([FromBody] RefreshTokenDto request)
    {
        var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        if (!await _tokenService.ValidateExpiredTokenAsync(token))
        {
            return BadRequest(new AuthenticationResponse().AddError("Invalid Request"));
        }

        var user = await _userManager.FindByNameAsync(_tokenService.GetUserName(token));
        if (user is null)
        {
            return BadRequest(new AuthenticationResponse().AddError("Invalid Request"));
        }

        if (user.RefreshToken != request.RefreshToken)
        {
            return BadRequest(new AuthenticationResponse().AddError("Invalid Request"));
        }

        if (user.RefreshTokenExpiresAt < DateTime.UtcNow)
        {
            return BadRequest(new AuthenticationResponse().AddError("Refresh token has expired"));
        }

        var roles = await _userManager.GetRolesAsync(user);
        var newToken = await _tokenService.CreateTokenAsync(user, roles);

        return Ok(AuthenticationResponse.WithToken(newToken));
    }

    /// <summary>
    /// Endpoint to initiate the forgot password process. Generates a password reset token and sends an email with the reset link.
    /// </summary>
    /// <param name="request">ForgotPasswordDto type</param>
    /// <returns>ApiResponse indicating the result of the operation</returns>
    [HttpPost("forgotpassword")]
    public async Task<IActionResult> ForgotPasswordAsync([FromBody] ForgotPasswordDto request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null || !await _userManager.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        // TODO: Create a simple reset page and use that as default if one isn't provided by the client /nb
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var resetPasswordUri = AccountHelpers.GenerateResetPasswordUri(user.Email!, token, request.CallbackUri!);

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
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null || !await _userManager.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        var resetResult = await _userManager.ResetPasswordAsync(user, request.Token!, request.NewPassword!);
        if (!resetResult.Succeeded)
        {
            var errors = resetResult.Errors.Select(e => e.Description);
            return BadRequest(new ApiResponse().AddErrors(errors));
        }

        await InvalidateUserTokens(user);

        // TODO: Create a simple lockout page and use that as default if one isn't provided by the client /nb
        var lockoutToken = await _userManager.GenerateUserTokenAsync(user, MfaProviders.Email.ToString(), "Lockout");
        var resetPasswordUri = AccountHelpers.GenerateLockoutUri(user.Email!, lockoutToken, request.CallbackUri!);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Password Reset",
            $"Your password was reset at {DateTime.UtcNow} UTC. If you didn't make this request please click the following link to lock your account and contact a system administrator. {resetPasswordUri}");

        user.LockoutEnd = null;
        await _userManager.UpdateAsync(user);

        await _userManager.ResetAccessFailedCountAsync(user);

        return string.IsNullOrWhiteSpace(request.CallbackUri)
            ? Ok(new ApiResponse())
            : Redirect(request.CallbackUri);
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
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null || !await _userManager.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        var resetResult = await _userManager.ChangePasswordAsync(user, request.OldPassword!, request.NewPassword!);
        if (!resetResult.Succeeded)
        {
            var errors = resetResult.Errors.Select(e => e.Description);
            return BadRequest(new ApiResponse().AddErrors(errors));
        }

        var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        await InvalidateUserTokens(user, token);

        // TODO: Create a simple lockout page and use that as default if one isn't provided by the client /nb
        var lockoutToken = await _userManager.GenerateUserTokenAsync(user, MfaProviders.Email.ToString(), "Lockout");
        var resetPasswordUri = AccountHelpers.GenerateLockoutUri(user.Email!, lockoutToken, request.CallbackUri!);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Password Reset",
            $"Your password was reset at {DateTime.UtcNow} UTC. If you didn't make this request please click the following link to lock your account and contact a system administrator. {resetPasswordUri}");

        user.LockoutEnd = null;
        await _userManager.UpdateAsync(user);

        await _userManager.ResetAccessFailedCountAsync(user);

        return string.IsNullOrWhiteSpace(request.CallbackUri)
            ? Ok(new ApiResponse())
            : Redirect(request.CallbackUri);
    }

    /// <summary>
    /// Endpoint to log the user out. Invalidates the user's tokens and logs them out.
    /// </summary>
    /// <returns>ApiResponse</returns>
    [HttpGet("logout")]
    public async Task<IActionResult> LogoutAsync()
    {
        var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", string.Empty);

        var user = await _userManager.FindByNameAsync(_tokenService.GetUserName(token));
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError("Invalid Request"));
        }

        await InvalidateUserTokens(user, token);
        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Enables user to follow email link to lock out an account if password was changed without user consent
    /// </summary>
    /// <param name="token">Must have been generated in a previous step</param>
    /// <param name="request">LockAccountDto</param>
    /// <returns>ApiResponse</returns>
    [HttpPost("lock")]
    public async Task<IActionResult> LockAccountAsync([FromQuery] string token, [FromBody] LockAccountDto request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        if (!await _userManager.VerifyUserTokenAsync(user, MfaProviders.Email.ToString(), "Lockout", token))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        if (!string.Equals(user.UserName, request.UserName, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(user.Email, request.Email, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(user.FirstName, request.FirstName, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(user.LastName, request.LastName, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(user.Country, request.Country, StringComparison.OrdinalIgnoreCase)
            || user.DateOfBirth != request.DateOfBirth)
        {
            return BadRequest(new ApiResponse().AddError("User provided details are not correct"));
        }

        await InvalidateUserTokens(user);

        await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
        return Ok(new ApiResponse());
    }

    private async Task InvalidateUserTokens(User user, string? token = null)
    {
        await _userManager.UpdateSecurityStampAsync(user);
        user.RefreshToken = null;
        user.RefreshTokenExpiresAt = DateTime.MinValue;
        await _userManager.UpdateAsync(user);
        
        if (!string.IsNullOrEmpty(token))
        {
            await _tokenService.RevokeTokenAsync(token, Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty);
        }
    }

    private async Task SendConfirmEmailAsync(User user, string? callbackUri)
    {
        var host = $"{Request.Scheme}://{Request.Host}";
        var controllerPath = $"/api/{ControllerContext.ActionDescriptor.ControllerName.ToLower()}";
        var confirmEmailPath = $"{host}{controllerPath}/confirm/email";

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        var confirmEmailParams = new Dictionary<string, string>
        {
            { "token", token },
            { "email", user.Email! },
            { "callbackUri", callbackUri ?? string.Empty }
        };

        var confirmEmailUri = QueryHelpers.AddQueryString(confirmEmailPath, confirmEmailParams!);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Email Confirmation",
            $"To confirm your email address please click the following link: {confirmEmailUri}");
    }

    private async Task<IActionResult> RecordLoginFailedAttempt(User user)
    {
        await _userManager.AccessFailedAsync(user);
        if (await _userManager.IsLockedOutAsync(user))
        {
            var content = $"Your account is locked due to too many failed login attempts.";

            await _emailService.SendEmailAsync(
                user.Email!,
                "Locked account information",
                content);

            user.WaitingForTwoFactorAuthentication = false;
            await _userManager.UpdateAsync(user);

            await InvalidateUserTokens(user);

            return Unauthorized(new AuthenticationResponse().AddError(content));
        }

        return Unauthorized(new AuthenticationResponse().AddError("Authentication failed."));
    }
}