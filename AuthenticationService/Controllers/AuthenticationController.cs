using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Enums;
using AuthenticationService.Extensions;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

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
    /// Login. Returns an access + refresh token pair on success, or — if the user has MFA
    /// enabled — kicks off the MFA challenge instead and returns which method was used so
    /// the client knows what to prompt for.
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

            return await RecordLoginFailedAttempt(user);
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
                    var mfaToken = await _userService.GenerateMfaTokenAsync(user, TokenOptions.DefaultEmailProvider);
                    await _emailService.SendEmailAsync(
                        user.Email!,
                        EmailSubjects.MfaAuthenticationToken,
                        $"Your token is: {mfaToken}");
                    break;
                case MfaProviders.Phone:
                    return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.PhoneMfaNotSupported));
                case MfaProviders.Authenticator:
                    break;
            }

            _logger.LogInformation(
                SecurityEventIds.MfaChallengeIssued,
                "MFA challenge issued for {UserId} via {Provider}",
                user.Id,
                request.MfaProvider);

            user.WaitingForMfa = true;
            await _userService.UpdateAsync(user);

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

        return Ok(AuthenticationResponse.WithToken(token));
    }

    /// <summary>
    /// Step 2 of login when MFA is enabled. The client calls this with the code the user
    /// just typed in (from their authenticator app or email). On success, returns the
    /// access + refresh token pair just like a non-MFA login would have.
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

            return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidRequest));
        }

        if (!user.WaitingForMfa)
        {
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

            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.AccountLockedFailedAttempts));
        }

        if (!await _userService.VerifyMfaTokenAsync(user, request.MfaProvider.ToString()!, request.Token!))
        {
            _logger.LogWarning(
                SecurityEventIds.MfaFailed,
                "MFA verification failed for {UserId} from {IpAddress}",
                user.Id,
                Request.GetRemoteIpAddress());

            return await RecordLoginFailedAttempt(user);
        }

        _logger.LogInformation(
            SecurityEventIds.MfaVerified,
            "MFA verified for {UserId} from {IpAddress}",
            user.Id,
            Request.GetRemoteIpAddress());

        var roles = await _userService.GetRolesAsync(user);
        var ipAddress = Request.GetRemoteIpAddress();
        var token = await _tokenService.CreateTokenAsync(user, roles, familyId: null, ipAddress: ipAddress);

        await _userService.ResetAccessFailedCountAsync(user);

        user.WaitingForMfa = false;
        await _userService.UpdateAsync(user);

        _logger.LogInformation(
            SecurityEventIds.LoginSucceeded,
            "Login succeeded for {UserId} from {IpAddress}",
            user.Id,
            ipAddress);

        return Ok(AuthenticationResponse.WithToken(token));
    }

    /// <summary>
    /// Swaps an expired access token + its refresh token for a fresh pair. The expired
    /// access token must still be in the Authorization header — its claims are read
    /// (signature still validated, expiry skipped) to know which user is refreshing.
    ///
    /// <para>If the supplied refresh token has already been used, this is treated as theft:
    /// every active session for the user is revoked and the request returns 401.</para>
    /// </summary>
    /// <returns>AuthenticationResponse with valid token if successful</returns>
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
            // Reuse has already fired inside the service (all families revoked +
            // stamp rotated). Notify the user out-of-band, emit a security event, and respond
            // with a generic 401 so the attacker can't tell they've been caught.
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

        if (compromisedUser?.Email is null)
        {
            return;
        }

        try
        {
            await _emailService.SendEmailAsync(
                compromisedUser.Email,
                EmailSubjects.SuspiciousActivity,
                $"We detected suspicious activity on your account at {DateTime.UtcNow:u} UTC from IP {ipAddress}. " +
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
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var sub = User.FindFirst(ClaimConstants.Sub)?.Value ?? string.Empty;
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
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);
        var ipAddress = Request.GetRemoteIpAddress();

        var user = await _userService.FindByIdAsync(sub);
        if (user is null)
        {
            // User behind the token is gone.
            // Token presented is orphaned and shouldn't keep working — revoke it so the
            // auth service rejects every subsequent hit.
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

    private async Task<IActionResult> RecordLoginFailedAttempt(User user)
    {
        await _userService.AccessFailedAsync(user);
        if (await _userService.IsLockedOutAsync(user))
        {
                await _emailService.SendEmailAsync(
                user.Email!,
                EmailSubjects.LockedAccountInfo,
                ErrorMessages.AccountLockedFailedAttempts);

            user.WaitingForMfa = false;
            await _userService.UpdateAsync(user);

            await _userService.InvalidateUserTokensAsync(user, Request.GetRemoteIpAddress(), RevocationReasons.FailedLoginLockout);

            _logger.LogWarning(
                SecurityEventIds.FailedLoginLockoutTriggered,
                "Account locked due to failed-login threshold for {UserId} from {IpAddress}",
                user.Id,
                Request.GetRemoteIpAddress());

            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.AccountLockedFailedAttempts));
        }

        return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, "Authentication failed."));
    }
}
