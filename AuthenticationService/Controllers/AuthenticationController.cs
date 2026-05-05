using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Extensions;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthenticationService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IEmailService _emailService;
    private readonly ITokenService _tokenService;
    private readonly IUserService _userService;
    private readonly ILogger<AuthenticationController> _logger;

    public AuthenticationController(
        IEmailService emailService,
        ITokenService tokenService,
        IUserService userService,
        ILogger<AuthenticationController> logger)
    {
        _emailService = emailService;
        _tokenService = tokenService;
        _userService = userService;
        _logger = logger;
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
            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessageConstants.InvalidRequest));
        }

        if (!await _userService.IsEmailConfirmedAsync(user))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Email is not confirmed"));
        }

        if (await _userService.IsLockedOutAsync(user))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.AccountLockedFailedAttempts));
        }

        if (!await _userService.CheckPasswordAsync(user, request.Password!))
        {
            return await RecordLoginFailedAttempt(user);
        }

        if (await _userService.GetTwoFactorEnabledAsync(user))
        {
            request.MfaProvider ??= user.Preferred2FAProvider;

            var providers = await _userService.GetValidTwoFactorProvidersAsync(user);
            if (!providers.Contains(request.MfaProvider.ToString()!))
            {
                return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.InvalidMfaProvider));
            }

            switch (request.MfaProvider)
            {
                case MfaProviders.Email:
                    var mfaToken = await _userService.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
                    await _emailService.SendEmailAsync(
                        user.Email!,
                        EmailSubjectConstants.MfaAuthenticationToken,
                        $"Your token is: {mfaToken}");
                    break;
                case MfaProviders.Phone:
                    return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessageConstants.PhoneMfaNotSupported));
                case MfaProviders.Authenticator:
                    break;
            }

            user.WaitingForTwoFactorAuthentication = true;
            await _userService.UpdateAsync(user);

            return Ok(AuthenticationResponse.WithMfaRequired(request.MfaProvider));
        }

        var roles = await _userService.GetRolesAsync(user);
        var ipAddress = Request.GetRemoteIpAddress();
        var token = await _tokenService.CreateTokenAsync(user, roles, familyId: null, ipAddress: ipAddress);

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
            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessageConstants.InvalidRequest));
        }

        if (!user.WaitingForTwoFactorAuthentication)
        {
            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessageConstants.InvalidRequest));
        }

        if (await _userService.IsLockedOutAsync(user))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.AccountLockedFailedAttempts));
        }

        if (!await _userService.VerifyTwoFactorTokenAsync(user, request.MfaProvider.ToString()!, request.Token!))
        {
            return await RecordLoginFailedAttempt(user);
        }

        var roles = await _userService.GetRolesAsync(user);
        var ipAddress = Request.GetRemoteIpAddress();
        var token = await _tokenService.CreateTokenAsync(user, roles, familyId: null, ipAddress: ipAddress);

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
        var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);
        if (!await _tokenService.ValidateExpiredTokenAsync(token))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.InvalidToken));
        }

        var ipAddress = Request.GetRemoteIpAddress();
        var result = await _tokenService.RotateRefreshTokenAsync(token, request.RefreshToken!, ipAddress);

        if (result is RefreshResult.Reused reused)
        {
            // Reuse has already fired inside the service (all families revoked +
            // stamp rotated). Notify the user out-of-band, emit a security event, and respond
            // with a generic 401 so the attacker can't tell they've been caught.
            await HandleReuseDetectedAsync(token, reused.FamilyId, ipAddress);
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.InvalidRefreshToken));
        }

        return result switch
        {
            RefreshResult.Success s => Ok(AuthenticationResponse.WithToken(s.Token)),
            RefreshResult.Expired => Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.ExpiredRefreshToken)),
            _ => Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.InvalidRefreshToken)),
        };
    }

    private async Task HandleReuseDetectedAsync(string accessToken, Guid familyId, string ipAddress)
    {
        var userId = _tokenService.GetUserId(accessToken);
        var compromisedUser = await _userService.FindByIdAsync(userId);

        _logger.LogWarning(
            "Refresh token reuse detected. UserId={UserId} FamilyId={FamilyId} IpAddress={IpAddress}",
            userId, familyId, ipAddress);

        if (compromisedUser?.Email is null)
        {
            return;
        }

        try
        {
            await _emailService.SendEmailAsync(
                compromisedUser.Email,
                EmailSubjectConstants.SuspiciousActivity,
                $"We detected suspicious activity on your account at {DateTime.UtcNow:u} UTC from IP {ipAddress}. " +
                "As a precaution, all your sessions have been signed out and you'll need to sign in again. " +
                "If this wasn't you, please change your password immediately.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Failed to send suspicious-activity email. UserId={UserId} FamilyId={FamilyId}",
                userId, familyId);
        }
    }

    /// <summary>
    /// Logs the caller out of this device only. Revokes the refresh-token family identified
    /// by the <c>sid</c> claim and adds the current access token to the deny-list. Other
    /// devices for the same user are unaffected.
    /// </summary>
    /// <returns>ApiResponse</returns>
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> LogoutAsync()
    {
        var sidStr = User.FindFirst(ClaimConstants.Sid)?.Value;
        if (!Guid.TryParse(sidStr, out var familyId))
        {
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.InvalidToken));
        }

        var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);
        var ipAddress = Request.GetRemoteIpAddress();

        await _tokenService.RevokeFamilyAsync(familyId, "logout");
        await _tokenService.RevokeTokenAsync(token, ipAddress);

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Logs the caller out of every device. Revokes every refresh-token family for the user,
    /// rotates the security stamp (kills outstanding access tokens), and adds the current
    /// access token to the deny-list. After this, every device that was logged in must re-authenticate.
    /// </summary>
    /// <returns>ApiResponse</returns>
    [Authorize]
    [HttpPost("logoutall")]
    public async Task<IActionResult> LogoutAllAsync()
    {
        var sub = User.FindFirst(ClaimConstants.Sub)?.Value;
        if (string.IsNullOrEmpty(sub))
        {
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.InvalidToken));
        }

        var user = await _userService.FindByIdAsync(sub);
        if (user is null)
        {
            return Ok(new ApiResponse());
        }

        var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);
        var ipAddress = Request.GetRemoteIpAddress();

        await _userService.InvalidateUserTokensAsync(user, ipAddress, token);
        return Ok(new ApiResponse());
    }

    private async Task<IActionResult> RecordLoginFailedAttempt(User user)
    {
        await _userService.AccessFailedAsync(user);
        if (await _userService.IsLockedOutAsync(user))
        {
                await _emailService.SendEmailAsync(
                user.Email!,
                EmailSubjectConstants.LockedAccountInfo,
                ErrorMessageConstants.AccountLockedFailedAttempts);

            user.WaitingForTwoFactorAuthentication = false;
            await _userService.UpdateAsync(user);

            await _userService.InvalidateUserTokensAsync(user, Request.GetRemoteIpAddress());

            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessageConstants.AccountLockedFailedAttempts));
        }

        return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Authentication failed."));
    }
}
