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
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthenticationService.Controllers;

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
                    mfaToken = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
                    // TODO: Send via SMS /nb
                    break;
                case MfaProviders.Authenticator:
                    // TODO: Anything we need to do with authenticator app ? /nb
                    break;
            }

            user.WaitingForTwoFactorAuthentication = true;
            await _userManager.UpdateAsync(user);

            return Ok(AuthenticationResponse.WithMfaRequired(request.MfaProvider));
        }

        var roles = await _userManager.GetRolesAsync(user);
        var token = _tokenService.CreateToken(user, roles);

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
        var token = _tokenService.CreateToken(user, roles);

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
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        var userNameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);

        var user = await _userManager.FindByNameAsync(userNameClaim!.Value);
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
                response = new EnableMfaResponse(MfaProviders.Phone);
                break;
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
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null || !await _userManager.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var resetPasswordUri = GenerateResetPasswordUri(user.Email!, token, request.CallbackUri!);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Password Reset",
            $"To reset your password, please click the following link: {resetPasswordUri}");

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Endpoint to reset the user's password using the provided token.
    /// </summary>
    /// <param name="request">ResetPasswordDto type</param>
    /// <returns>ApiResponse indicating the result of the operation</returns>
    [HttpPost("resetpassword")]
    public async Task<IActionResult> ResetPasswordAsync([FromBody] ResetPasswordDto request)
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

        await InvalidateAllUserTokens(user);

        user.LockoutEnd = null;
        await _userManager.UpdateAsync(user);

        await _userManager.ResetAccessFailedCountAsync(user);

        return string.IsNullOrWhiteSpace(request.CallbackUri)
            ? Ok(new ApiResponse())
            : Redirect(request.CallbackUri);
    }

    private async Task InvalidateAllUserTokens(User user)
    {
        await _userManager.UpdateSecurityStampAsync(user);
        //user.RefreshToken = null;
        //user.RefreshTokenExpiryTime = DateTime.MinValue;
        await _userManager.UpdateAsync(user);
    }

    private string GenerateResetPasswordUri(string email, string token, string callbackUri)
    {
        var resetPasswordParams = new Dictionary<string, string>
        {
            { "token", token },
            { "email", email }
        };

        return QueryHelpers.AddQueryString(callbackUri, resetPasswordParams!);
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

            return Unauthorized(new AuthenticationResponse().AddError(content));
        }

        return Unauthorized(new AuthenticationResponse().AddError("Authentication failed."));
    }
}