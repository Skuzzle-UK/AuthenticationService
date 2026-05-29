using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AuthenticationService.Extensions;
using AuthenticationService.Helpers;
using AuthenticationService.Observability;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using AuthenticationService.Shared.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.Text;

namespace AuthenticationService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IEmailService _emailService;
    private readonly ISmsService _smsService;
    private readonly ITokenService _tokenService;
    private readonly IUserService _userService;
    private readonly PublicUrlSettings _publicUrlSettings;
    private readonly ILogger<AuthenticationController> _logger;
    private readonly AuthMetrics _metrics;

    public AuthenticationController(
        IEmailService emailService,
        ISmsService smsService,
        ITokenService tokenService,
        IUserService userService,
        IOptions<PublicUrlSettings> publicUrlSettings,
        ILogger<AuthenticationController> logger,
        AuthMetrics metrics)
    {
        _emailService = emailService;
        _smsService = smsService;
        _tokenService = tokenService;
        _userService = userService;
        _publicUrlSettings = publicUrlSettings.Value;
        _logger = logger;
        _metrics = metrics;
    }

    /// <summary>
    /// Login. Returns access + refresh tokens on success, or kicks off the MFA challenge if MFA is enabled.
    /// </summary>
    [HttpPost("authenticate")]
    [EnableRateLimiting(RateLimitPolicies.AuthStrict)]
    public async Task<IActionResult> AuthenticateAsync([FromBody] AuthenticationDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            _logger.LogWarning(
                SecurityEventIds.LoginFailed,
                "Login failed for {UserId} from {IpAddress} ({Reason})",
                string.Empty,
                Request.GetRemoteIpAddress(),
                LoginFailureReason.BadCredentials);
            
            _metrics.LoginFailed(LoginFailureReason.BadCredentials);

            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidRequest));
        }

        if (!await _userService.IsEmailConfirmedAsync(user))
        {
            _logger.LogWarning(
                SecurityEventIds.LoginFailed,
                "Login failed for {UserId} from {IpAddress} ({Reason})",
                user.Id,
                Request.GetRemoteIpAddress(),
                LoginFailureReason.EmailNotConfirmed);
            
            _metrics.LoginFailed(LoginFailureReason.EmailNotConfirmed);

            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Email is not confirmed"));
        }

        if (await _userService.IsLockedOutAsync(user))
        {
            _logger.LogWarning(
                SecurityEventIds.LoginFailed,
                "Login failed for {UserId} from {IpAddress} ({Reason})",
                user.Id,
                Request.GetRemoteIpAddress(),
                LoginFailureReason.AccountLocked);
            
            _metrics.LoginFailed(LoginFailureReason.AccountLocked);

            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.AccountLockedFailedAttempts));
        }

        if (!await _userService.CheckPasswordAsync(user, request.Password!))
        {
            _logger.LogWarning(
                SecurityEventIds.LoginFailed,
                "Login failed for {UserId} from {IpAddress} ({Reason})",
                user.Id,
                Request.GetRemoteIpAddress(),
                LoginFailureReason.BadCredentials);
            
            _metrics.LoginFailed(LoginFailureReason.BadCredentials);

            return await RecordLoginFailedAttempt(user, request.ResetPasswordUri);
        }

        if (await _userService.GetMfaEnabledAsync(user))
        {
            request.MfaProvider ??= user.PreferredMfaProvider;

            var providers = await _userService.GetValidMfaProvidersAsync(user);
            if (!providers.Contains(request.MfaProvider.ToString()!))
            {
                return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidMfaProvider));
            }

            switch (request.MfaProvider)
            {
                case MfaProviders.Email:
                    var emailMfaToken = await _userService.GenerateMfaTokenAsync(user, TokenOptions.DefaultEmailProvider);
                    await _emailService.SendEmailAsync(
                        user.Email!,
                        EmailSubjects.MfaAuthenticationToken,
                        $"Your token is: {emailMfaToken}");
                    break;
                case MfaProviders.Phone:
                    if (!_smsService.IsConfigured)
                    {
                        return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.PhoneMfaNotConfigured));
                    }
                    if (string.IsNullOrEmpty(user.PhoneNumber) || !user.PhoneNumberConfirmed)
                    {
                        return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.PhoneNumberNotConfirmed));
                    }
                    var smsMfaToken = await _userService.GenerateMfaTokenAsync(user, TokenOptions.DefaultPhoneProvider);
                    await _smsService.SendAsync(user.PhoneNumber, $"Your authentication code is: {smsMfaToken}");
                    break;
                case MfaProviders.Authenticator:
                    break;
            }

            _logger.LogInformation(
                SecurityEventIds.MfaChallengeIssued,
                "MFA challenge issued for {UserId} via {Provider}",
                user.Id,
                request.MfaProvider);
            
            _metrics.MfaChallengeIssued(request.MfaProvider!.Value);

            return Ok(AuthenticationResponse.WithMfaRequired(request.MfaProvider));
        }

        var roles = await _userService.GetRolesAsync(user);
        var ipAddress = Request.GetRemoteIpAddress();
        var token = await _tokenService.CreateTokenAsync(user, roles, familyId: null, ipAddress: ipAddress);

        await _userService.ResetAccessFailedCountAsync(user);

        _logger.LogInformation(
            SecurityEventIds.LoginSucceeded,
            "Login succeeded for {UserId} from {IpAddress}",
            user.Id,
            ipAddress);
        
        _metrics.LoginSucceeded(mfaUsed: false);

        return Ok(AuthenticationResponse.WithToken(token));
    }

    /// <summary>
    /// Step 2 of MFA login. Verifies the user-supplied code and returns access + refresh tokens on success.
    /// </summary>
    [HttpPost("mfa")]
    [EnableRateLimiting(RateLimitPolicies.AuthStrict)]
    public async Task<IActionResult> MfaAuthenticateAsync([FromBody] MfaAuthenticationDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            _logger.LogWarning(
                SecurityEventIds.LoginFailed,
                "Login failed for {UserId} from {IpAddress} ({Reason})",
                string.Empty,
                Request.GetRemoteIpAddress(),
                LoginFailureReason.BadCredentials);
            
            _metrics.LoginFailed(LoginFailureReason.BadCredentials);

            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidRequest));
        }

        if (await _userService.IsLockedOutAsync(user))
        {
            _logger.LogWarning(
                SecurityEventIds.LoginFailed,
                "Login failed for {UserId} from {IpAddress} ({Reason})",
                user.Id,
                Request.GetRemoteIpAddress(),
                LoginFailureReason.AccountLocked);
            
            _metrics.LoginFailed(LoginFailureReason.AccountLocked);

            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.AccountLockedFailedAttempts));
        }

        if (!await _userService.VerifyMfaTokenAsync(user, request.MfaProvider.ToString()!, request.Token!))
        {
            _logger.LogWarning(
                SecurityEventIds.MfaFailed,
                "MFA verification failed for {UserId} from {IpAddress}",
                user.Id,
                Request.GetRemoteIpAddress());
            
            _metrics.MfaFailed();

            return await RecordLoginFailedAttempt(user, request.ResetPasswordUri);
        }

        _logger.LogInformation(
            SecurityEventIds.MfaVerified,
            "MFA verified for {UserId} from {IpAddress}",
            user.Id,
            Request.GetRemoteIpAddress());
        
        _metrics.MfaVerified();

        var roles = await _userService.GetRolesAsync(user);
        var ipAddress = Request.GetRemoteIpAddress();
        var token = await _tokenService.CreateTokenAsync(user, roles, familyId: null, ipAddress: ipAddress);

        await _userService.ResetAccessFailedCountAsync(user);

        _logger.LogInformation(
            SecurityEventIds.LoginSucceeded,
            "Login succeeded for {UserId} from {IpAddress}",
            user.Id,
            ipAddress);
        
        _metrics.LoginSucceeded(mfaUsed: true);

        return Ok(AuthenticationResponse.WithToken(token));
    }

    /// <summary>
    /// Swaps an expired access token + refresh token for a fresh pair. Reuse of a refresh token is treated as theft — every session for the user is revoked.
    /// </summary>
    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshTokenAsync([FromBody] RefreshTokenDto request)
    {
        var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);
        if (!await _tokenService.ValidateExpiredTokenAsync(token))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var ipAddress = Request.GetRemoteIpAddress();
        var result = await _tokenService.RotateRefreshTokenAsync(token, request.RefreshToken!, ipAddress);

        if (result is RefreshResult.Reused reused)
        {
            // Service already revoked families + rotated stamp. Notify user out-of-band; respond with a generic 401 so the attacker can't tell they've been caught.
            await HandleReuseDetectedAsync(token, reused.FamilyId, ipAddress);
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidRefreshToken));
        }

        if (result is RefreshResult.Success success)
        {
            _logger.LogInformation(
                SecurityEventIds.RefreshTokenRotated,
                "Refresh token rotated for {UserId} from {IpAddress}",
                _tokenService.GetUserId(token),
                ipAddress);
            
            _metrics.RefreshTokenRotated();

            return Ok(AuthenticationResponse.WithToken(success.Token));
        }

        return result switch
        {
            RefreshResult.Expired => Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.ExpiredRefreshToken)),
            _ => Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidRefreshToken)),
        };
    }

    private async Task HandleReuseDetectedAsync(string accessToken, Guid familyId, string ipAddress)
    {
        var userId = _tokenService.GetUserId(accessToken);
        var compromisedUser = await _userService.FindByIdAsync(userId);

        _logger.LogCritical(
            SecurityEventIds.RefreshTokenReuseDetected,
            "Refresh token reuse detected for {UserId} family {FamilyId} from {IpAddress}",
            userId,
            familyId,
            ipAddress);
        
        _metrics.RefreshTokenReuseDetected();

        if (compromisedUser?.Email is null)
        {
            return;
        }

        try
        {
            await _emailService.SendEmailAsync(
                compromisedUser.Email,
                EmailSubjects.SuspiciousActivity,
                $"We detected suspicious activity on your account at {DateTimeOffset.UtcNow:u} UTC from IP {ipAddress}. " +
                "As a precaution, all your sessions have been signed out and you'll need to sign in again. " +
                "If this wasn't you, please change your password immediately.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Failed to send suspicious-activity email. UserId={UserId} FamilyId={FamilyId}",
                userId,
                familyId);
        }
    }

    /// <summary>
    /// Logs the caller out of this device only. Revokes the refresh-token family from the sid claim and deny-lists the current access token.
    /// </summary>
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> LogoutAsync()
    {
        var sidStr = User.FindFirst(ClaimConstants.Sid)?.Value;
        if (!Guid.TryParse(sidStr, out var familyId))
        {
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var sub = User.GetUserIdOrEmpty();
        var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);
        var ipAddress = Request.GetRemoteIpAddress();

        await _tokenService.RevokeFamilyAsync(familyId, RevocationReasons.Logout);
        await _tokenService.RevokeTokenAsync(token, ipAddress, RevocationReasons.Logout);

        _logger.LogInformation(
            SecurityEventIds.LogoutPerDevice,
            "Per-device logout for {UserId} family {FamilyId} from {IpAddress}",
            sub,
            familyId,
            ipAddress);

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Logs the caller out of every device. Revokes all refresh-token families, rotates the security stamp, and deny-lists the current access token.
    /// </summary>
    [Authorize]
    [HttpPost("logoutall")]
    public async Task<IActionResult> LogoutAllAsync()
    {
        var sub = User.GetUserId();
        if (string.IsNullOrEmpty(sub))
        {
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);
        var ipAddress = Request.GetRemoteIpAddress();

        var user = await _userService.FindByIdAsync(sub);
        if (user is null)
        {
            // Orphan token — revoke so subsequent hits are rejected.
            await _tokenService.RevokeOrphanedTokenAsync(token, ipAddress);
            return Ok(new ApiResponse());
        }

        await _userService.InvalidateUserTokensAsync(user, ipAddress, RevocationReasons.LogoutAll, token);

        _logger.LogInformation(
            SecurityEventIds.LogoutAllDevices,
            "Log-out-all-devices for {UserId} from {IpAddress}",
            sub,
            ipAddress);

        return Ok(new ApiResponse());
    }

    private async Task<IActionResult> RecordLoginFailedAttempt(User user, string? resetPasswordUri)
    {
        await _userService.AccessFailedAsync(user);
        if (await _userService.IsLockedOutAsync(user))
        {
            await SendFailedLoginLockoutEmailAsync(user, resetPasswordUri);

            await _userService.InvalidateUserTokensAsync(user, Request.GetRemoteIpAddress(), RevocationReasons.FailedLoginLockout);

            _logger.LogWarning(
                SecurityEventIds.FailedLoginLockoutTriggered,
                "Account locked due to failed-login threshold for {UserId} from {IpAddress}",
                user.Id,
                Request.GetRemoteIpAddress());
            
            _metrics.LockoutTriggered("failed_login");

            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.AccountLockedFailedAttempts));
        }

        return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Authentication failed."));
    }

    // Email send failures are logged but don't block — lock has already happened.
    private async Task SendFailedLoginLockoutEmailAsync(User user, string? resetPasswordUri)
    {
        if (string.IsNullOrEmpty(user.Email))
        {
            return;
        }

        try
        {
            var baseResetUri = string.IsNullOrWhiteSpace(resetPasswordUri)
                ? $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.ResetPassword}"
                : resetPasswordUri;

            var token = await _userService.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var resetUri = AccountHelpers.GenerateResetPasswordUri(user.Email, encodedToken, baseResetUri);

            await _emailService.SendEmailAsync(
                user.Email,
                EmailSubjects.LockedAccountInfo,
                "Your account has been locked because of too many failed login attempts. " +
                "The lockout will clear automatically in a few minutes — you can simply wait and try again. " +
                $"If you weren't the one trying to log in, please reset your password now using this link to lock the attacker out for good: {resetUri}");
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to send failed-login lockout email to {UserId}: {ErrorMsg}",
                user.Id,
                ex.Message);
        }
    }
}
