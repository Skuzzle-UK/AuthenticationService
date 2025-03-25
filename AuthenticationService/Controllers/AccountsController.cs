using AuthenticationService.Entities;
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
using QRCoder;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Encodings.Web;

namespace AuthenticationService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountsController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly IEmailService _emailService;
    private readonly ITokenService _tokenService;
    private readonly IMapper _mapper;
    private readonly UrlEncoder _urlEncoder;
    private readonly DatabaseContext _dbContext;

    public AccountsController(
        UserManager<User> userManager,
        IEmailService emailService,
        ITokenService tokenService,
        IMapper mapper,
        UrlEncoder urlEncoder,
        DatabaseContext dbContext)
    {
        _userManager = userManager;
        _emailService = emailService;
        _tokenService = tokenService;
        _mapper = mapper;
        _urlEncoder = urlEncoder;
        _dbContext = dbContext;
    }

    // TODO: Endpoint to resend email confirmation request /nb
    // TODO: Forgot/Reset password methods /nb
    // TODO: Ensure reset method has setlockoutenddate and set to null

    [HttpPost("register")]
    public async Task<IActionResult> RegisterUserAsync([FromBody] RegistrationDto request)
    {
        if (request is null)
        {
            return BadRequest();
        }

        using var transaction = await _dbContext.Database.BeginTransactionAsync();

        try
        {
            var user = _mapper.Map<User>(request);
            var result = await _userManager.CreateAsync(user, request.Password!);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description);

                return BadRequest(new RegistrationResponse { Errors = errors });
            }

            if (request.Preferred2FAProvider is not null)
            {
                user.Preferred2FAProvider = request.Preferred2FAProvider.Value;
                await _userManager.UpdateAsync(user);
            }

            await _userManager.AddToRoleAsync(user, "User");

            var host = $"{Request.Scheme}://{Request.Host}";
            var controllerPath = $"/api/{ControllerContext.ActionDescriptor.ControllerName.ToLower()}";
            var confirmEmailPath = $"{host}{controllerPath}/confirm/email";

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmEmailParams = new Dictionary<string, string>
            {
                { "token", token },
                { "email", user.Email! },
                { "callbackUri", request.EmailConfirmationCallbackUri ?? string.Empty }
            };

            var confirmEmailUri = QueryHelpers.AddQueryString(confirmEmailPath, confirmEmailParams!);

            await _emailService.SendEmailAsync(
                user.Email!,
                "Email Confirmation",
                $"To confirm your email address please click the following link: {confirmEmailUri}");

            await transaction.CommitAsync();

            return Created();
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return StatusCode(500, ex.Message);
        }
    }

    [HttpGet("confirm/email")]
    public async Task<IActionResult> ConfirmEmailAsync([FromQuery] string email, [FromQuery] string token, [FromQuery] string? callbackUri)
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

        return string.IsNullOrWhiteSpace(callbackUri)
            ? Ok("Your email is now confirmed")
            : Redirect(callbackUri);
    }

    [HttpPost("authenticate")]
    public async Task<IActionResult> AuthenticateAsync([FromBody] AuthenticationDto request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest("Invalid Request");
        }

        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            return Unauthorized(new AuthenticationResponse { ErrorMessage = "Email is not confirmed" });
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return Unauthorized(new AuthenticationResponse { ErrorMessage = "The account is locked due to to many failed login attempts" });
        }

        if (!await _userManager.CheckPasswordAsync(user, request.Password!))
        {
            await _userManager.AccessFailedAsync(user);
            if (await _userManager.IsLockedOutAsync(user))
            {
                var content = $"Your account is locked out due to to many failed login attempts.";

                await _emailService.SendEmailAsync(
                    user.Email!,
                    "Locked account information",
                    "Your account is locked out due to to many failed login attempts.");

                return Unauthorized(new AuthenticationResponse { ErrorMessage = content });
            }
            return Unauthorized(new AuthenticationResponse { ErrorMessage = "Invalid Authentication" });
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
                return Unauthorized(new AuthenticationResponse { ErrorMessage = "Invalid MFA Provider" });
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

            return Ok(new AuthenticationResponse { MfaRequired = true, MfaProvider = request.MfaProvider.ToString() });
        }

        var roles = await _userManager.GetRolesAsync(user);
        var token = _tokenService.CreateToken(user, roles);

        await _userManager.ResetAccessFailedCountAsync(user);

        return Ok(new AuthenticationResponse { IsSuccessful = true, Token = token });
    }

    [HttpPost("authenticate/mfa")]
    public async Task<IActionResult> MfaAuthenticateAsync([FromBody] MfaAuthenticationDto request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest("Invalid Request");
        }

        if (!user.WaitingForTwoFactorAuthentication)
        {
            return BadRequest("Invalid Request");
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return Unauthorized(new AuthenticationResponse { ErrorMessage = "The account is locked due to to many failed login attempts" });
        }

        if (!await _userManager.VerifyTwoFactorTokenAsync(user, request.MfaProvider!, request.Token!))
        {
            await _userManager.AccessFailedAsync(user);
            if (await _userManager.IsLockedOutAsync(user))
            {
                var content = $"Your account is locked out due to to many failed login attempts.";

                await _emailService.SendEmailAsync(
                    user.Email!,
                    "Locked account information",
                    content);

                user.WaitingForTwoFactorAuthentication = false;
                await _userManager.UpdateAsync(user);

                return Unauthorized(new AuthenticationResponse { ErrorMessage = content });
            }

            return Unauthorized(new AuthenticationResponse { ErrorMessage = "MFA authentication failed." });
        }

        var roles = await _userManager.GetRolesAsync(user);
        var token = _tokenService.CreateToken(user, roles);

        await _userManager.ResetAccessFailedCountAsync(user);

        user.WaitingForTwoFactorAuthentication = false;
        await _userManager.UpdateAsync(user);

        return Ok(new AuthenticationResponse { IsSuccessful = true, Token = token });
    }

    [HttpGet("enablemfa")]
    [Authorize]
    public async Task<IActionResult> EnableMfaAsync(EnableMfaRequest request)
    {
        var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        var userNameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");

        var user = await _userManager.FindByNameAsync(userNameClaim!.Value);
        if(user is null)
        {
            return BadRequest("Invalid Request");
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);

        if (request.Preferred2FAProvider is not null)
        {
            user.Preferred2FAProvider = request.Preferred2FAProvider.Value;
            await _userManager.UpdateAsync(user);
        }

        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if(string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        dynamic? response = null;

        switch (user.Preferred2FAProvider)
        {
            case MfaProviders.Email:
                break;
            case MfaProviders.Phone:
                break;
            case MfaProviders.Authenticator:
                var uri = GenerateQRCodeUri(user.Email!, key!);
                {
                    using var qrGenerator = new QRCodeGenerator();
                    using var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
                    using var qrCode = new PngByteQRCode(qrCodeData);
                    response = qrCode.GetGraphic(20);
                }
                break;
        }

        return Ok(response);
    }

    private string GenerateQRCodeUri(string email, string key)
    {
        var keyEncoded = _urlEncoder.Encode(key);
        var emailEncoded = _urlEncoder.Encode(email);
        return $"otpauth://totp/AuthenticationService:{emailEncoded}?secret={keyEncoded}&issuer=AuthenticationService&digits=6";
    }
}