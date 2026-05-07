using AuthenticationService.Constants;
using AuthenticationService.Extensions;
using AuthenticationService.Helpers;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Shared.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.Text;

namespace AuthenticationService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly IEmailService _emailService;
    private readonly ISmsService _smsService;
    private readonly ITokenService _tokenService;
    private readonly IUserService _userService;
    private readonly PublicUrlSettings _publicUrlSettings;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        IEmailService emailService,
        ISmsService smsService,
        ITokenService tokenService,
        IUserService userService,
        IOptions<PublicUrlSettings> publicUrlSettings,
        ILogger<AccountController> logger)
    {
        _emailService = emailService;
        _smsService = smsService;
        _tokenService = tokenService;
        _userService = userService;
        _publicUrlSettings = publicUrlSettings.Value;
        _logger = logger;
    }

    /// <summary>
    /// Returns the current snapshot of the logged-in user's profile + roles. Useful for
    /// SPAs that want to render user info without parsing the JWT, and for developers
    /// debugging "is my token still valid?" — a 200 here means the token is signed,
    /// unexpired, not revoked, and the user behind it still exists.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> MeAsync()
    {
        var sub = User.FindFirst(ClaimConstants.Sub)?.Value;
        if (string.IsNullOrEmpty(sub))
        {
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var user = await _userService.FindByIdAsync(sub);
        if (user is null)
        {
            // Token references a user that no longer exists.
            // Revoke it so this auth service rejects every subsequent hit
            var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);
            await _tokenService.RevokeOrphanedTokenAsync(token, Request.GetRemoteIpAddress());

            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var roles = await _userService.GetRolesAsync(user);

        return Ok(new MeResponse
        {
            Id = user.Id,
            UserName = user.UserName!,
            Email = user.Email!,
            EmailConfirmed = user.EmailConfirmed,
            FirstName = user.FirstName,
            LastName = user.LastName,
            DateOfBirth = user.DateOfBirth,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            Country = user.Country,
            AddressLine1 = user.AddressLine1,
            AddressLine2 = user.AddressLine2,
            AddressLine3 = user.AddressLine3,
            City = user.City,
            Postcode = user.Postcode,
            MfaEnabled = await _userService.GetMfaEnabledAsync(user),
            PreferredMfaProvider = user.PreferredMfaProvider,
            Roles = roles,
        });
    }

    /// <summary>
    /// Updates editable profile fields on the logged-in user. Each field on the body is
    /// optional — only the supplied ones are written, the rest are left untouched. Returns
    /// 200 with an empty <see cref="ApiResponse"/> on success; clients should re-fetch
    /// <c>GET /me</c> if they need the post-update snapshot.
    ///
    /// <para>Changing <c>PhoneNumber</c> resets the phone-confirmed flag — the user must
    /// re-confirm before SMS-based MFA will work against the new number. Username, email,
    /// password, MFA, and roles are out of scope here — they each have a dedicated flow.</para>
    /// </summary>
    [HttpPut("me")]
    [Authorize]
    [EnableRateLimiting(RateLimitPolicies.AuthSensitive)]
    public async Task<IActionResult> UpdateProfileAsync([FromBody] UpdateProfileDto request)
    {
        if (request is null)
        {
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidRequest));
        }

        var sub = User.FindFirst(ClaimConstants.Sub)?.Value;
        if (string.IsNullOrEmpty(sub))
        {
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var user = await _userService.FindByIdAsync(sub);
        if (user is null)
        {
            // Token references a user that no longer exists — same defensive revoke as GET /me.
            var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);
            await _tokenService.RevokeOrphanedTokenAsync(token, Request.GetRemoteIpAddress());

            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var changedFields = new List<string>();

        if (request.FirstName is not null && request.FirstName != user.FirstName)
        {
            user.FirstName = request.FirstName;
            changedFields.Add(nameof(user.FirstName));
        }

        if (request.LastName is not null && request.LastName != user.LastName)
        {
            user.LastName = request.LastName;
            changedFields.Add(nameof(user.LastName));
        }

        if (request.DateOfBirth is not null && request.DateOfBirth != user.DateOfBirth)
        {
            user.DateOfBirth = request.DateOfBirth;
            changedFields.Add(nameof(user.DateOfBirth));
        }

        if (request.PhoneNumber is not null && request.PhoneNumber != user.PhoneNumber)
        {
            user.PhoneNumber = request.PhoneNumber;
            // Number changed — old confirmation no longer applies. SMS-MFA paths block on
            // PhoneNumberConfirmed so clearing this is what gates them off.
            user.PhoneNumberConfirmed = false;
            changedFields.Add(nameof(user.PhoneNumber));
        }

        if (request.Country is not null && request.Country != user.Country)
        {
            user.Country = request.Country;
            changedFields.Add(nameof(user.Country));
        }

        if (request.AddressLine1 is not null && request.AddressLine1 != user.AddressLine1)
        {
            user.AddressLine1 = request.AddressLine1;
            changedFields.Add(nameof(user.AddressLine1));
        }

        if (request.AddressLine2 is not null && request.AddressLine2 != user.AddressLine2)
        {
            user.AddressLine2 = request.AddressLine2;
            changedFields.Add(nameof(user.AddressLine2));
        }

        if (request.AddressLine3 is not null && request.AddressLine3 != user.AddressLine3)
        {
            user.AddressLine3 = request.AddressLine3;
            changedFields.Add(nameof(user.AddressLine3));
        }

        if (request.City is not null && request.City != user.City)
        {
            user.City = request.City;
            changedFields.Add(nameof(user.City));
        }

        if (request.Postcode is not null && request.Postcode != user.Postcode)
        {
            user.Postcode = request.Postcode;
            changedFields.Add(nameof(user.Postcode));
        }

        if (changedFields.Count == 0)
        {
            // Nothing actually differed — skip the round-trip and the audit event.
            return Ok(new ApiResponse());
        }

        await _userService.UpdateAsync(user);

        _logger.LogInformation(
            SecurityEventIds.ProfileUpdated,
            "Profile updated for {UserId} from {IpAddress} ({Fields})",
            user.Id,
            Request.GetRemoteIpAddress(),
            string.Join(",", changedFields));

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Starts MFA enrolment for the logged-in user. Returns the shared secret and a QR code
    /// the user can scan into an authenticator app, or the verification details for the
    /// chosen non-app provider (e.g. email).
    /// </summary>
    /// <param name="request">EnableMfaRequest</param>
    /// <returns>EnableMfaResponse which contains a valid QrCode if requesting to use authenticator app</returns>
    [HttpGet("enablemfa")]
    [Authorize]
    [EnableRateLimiting(RateLimitPolicies.AuthSensitive)]
    public async Task<IActionResult> EnableMfaAsync(EnableMfaRequest request)
    {
        var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);

        var user = await _userService.FindByIdAsync(_tokenService.GetUserId(token));
        if (user is null)
        {
            // Orphan token — user behind the sub claim is gone. Revoke it so the auth
            // service rejects every subsequent hit; return 401 (Unauthorized) rather than
            // the previous 400 since the failure is about the token, not the request body.
            await _tokenService.RevokeOrphanedTokenAsync(token, Request.GetRemoteIpAddress());
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        var key = await _userService.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userService.ResetAuthenticatorKeyAsync(user);
            key = await _userService.GetAuthenticatorKeyAsync(user);
        }

        var providers = await _userService.GetValidMfaProvidersAsync(user);
        if (!providers.Contains(request.PreferredMfaProvider.ToString()!))
        {
            return Unauthorized(new AuthenticationResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidMfaProvider));
        }

        var currentMfaStatus = await _userService.GetMfaEnabledAsync(user);

        await _userService.SetMfaEnabledAsync(user, true);

        if (request.PreferredMfaProvider is not null)
        {
            user.PreferredMfaProvider = request.PreferredMfaProvider.Value;
            await _userService.UpdateAsync(user);
        }

        var response = new EnableMfaResponse();

        switch (user.PreferredMfaProvider)
        {
            case MfaProviders.Email:
                response = new EnableMfaResponse(MfaProviders.Email);
                break;
            case MfaProviders.Phone:
                if (!_smsService.IsConfigured)
                {
                    // The user picked a provider this deployment can't actually deliver to.
                    await _userService.SetMfaEnabledAsync(user, currentMfaStatus);
                    return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.PhoneMfaNotConfigured));
                }
                if (string.IsNullOrEmpty(user.PhoneNumber) || !user.PhoneNumberConfirmed)
                {
                    await _userService.SetMfaEnabledAsync(user, currentMfaStatus);
                    return BadRequest(new AuthenticationResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.PhoneNumberNotConfirmed));
                }
                response = new EnableMfaResponse(MfaProviders.Phone);
                break;
            case MfaProviders.Authenticator:
                response = new EnableMfaResponse(
                    MfaProviders.Authenticator,
                    QrCodeHelpers.NewPng(user.Email!, key!),
                    key);
                break;
        }

        _logger.LogInformation(
            SecurityEventIds.MfaEnabled,
            "MFA enabled for {UserId} via {Provider}",
            user.Id,
            user.PreferredMfaProvider);

        return Ok(response);
    }

    /// <summary>
    /// Kicks off the "I forgot my password" flow. Sends an email with a single-use reset
    /// link. Returns 200 even when the email isn't recognised — we don't leak which
    /// addresses are registered.
    /// </summary>
    [HttpPost("forgotpassword")]
    [EnableRateLimiting(RateLimitPolicies.AuthStrict)]
    public async Task<IActionResult> ForgotPasswordAsync([FromBody] ForgotPasswordDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null || !await _userService.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidRequest));
        }

        var token = await _userService.GeneratePasswordResetTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        if (string.IsNullOrWhiteSpace(request.ResetPasswordUri))
        {
            request.ResetPasswordUri = $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.ResetPassword}";
        }

        var resetPasswordUri = AccountHelpers.GenerateResetPasswordUri(user.Email!, encodedToken, request.ResetPasswordUri);

        await _emailService.SendEmailAsync(
            user.Email!,
            EmailSubjects.PasswordReset,
            $"To reset your password, please click the following link: {resetPasswordUri}. If you didn't make this request please contact a system administrator.");

        _logger.LogInformation(
            SecurityEventIds.PasswordResetRequested,
            "Password reset requested for {UserId} from {IpAddress}",
            user.Id,
            Request.GetRemoteIpAddress());

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Sets a new password using the single-use token from a forgot-password email. Also
    /// clears any active lockout — this endpoint doubles as the account-recovery path.
    /// </summary>
    [HttpPost("forgotpassword/reset")]
    [EnableRateLimiting(RateLimitPolicies.AuthStrict)]
    public async Task<IActionResult> ResetForgottenPasswordAsync([FromBody] ResetForgottenPasswordDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null || !await _userService.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidRequest));
        }

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token!));

        var resetResult = await _userService.ResetPasswordAsync(user, decodedToken, request.NewPassword!);
        if (!resetResult.Succeeded)
        {
            var errors = resetResult.Errors.ToDictionary(e => e.Code, e => e.Description);
            return BadRequest(new ApiResponse().AddErrors(errors));
        }

        await _userService.InvalidateUserTokensAsync(user, Request.GetRemoteIpAddress(), RevocationReasons.PasswordReset);

        var lockoutToken = await _userService.GenerateUserTokenAsync(user, MfaProviders.Email.ToString(), TokenPurposes.Lockout);

        if (string.IsNullOrWhiteSpace(request.LockAccountUri))
        {
            request.LockAccountUri = $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.LockAccount}";
        }

        var lockAccountUri = AccountHelpers.GenerateLockoutUri(user.Email!, lockoutToken, request.LockAccountUri);

        await _emailService.SendEmailAsync(
            user.Email!,
            EmailSubjects.PasswordReset,
            $"Your password was reset at {DateTime.UtcNow} UTC. If you didn't make this request please click the following link to lock your account and contact a system administrator. {lockAccountUri}");

        user.LockoutEnd = null;
        await _userService.UpdateAsync(user);

        await _userService.ResetAccessFailedCountAsync(user);

        _logger.LogInformation(
            SecurityEventIds.PasswordResetCompleted,
            "Password reset completed for {UserId} from {IpAddress}",
            user.Id,
            Request.GetRemoteIpAddress());

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Changes the logged-in user's password. The user is identified from the token's
    /// <c>sub</c> claim — a user can never change anyone else's password through here, even
    /// if they pass a different email in the request body.
    /// </summary>
    [HttpPost("changepassword")]
    [Authorize]
    [EnableRateLimiting(RateLimitPolicies.AuthSensitive)]
    public async Task<IActionResult> ChangePasswordAsync([FromBody] ChangePasswordDto request)
    {
        var sub = User.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(sub))
        {
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidRequest));
        }

        var token = Request.Headers.Authorization.ToString().Replace(AuthSchemeConstants.BearerPrefix, string.Empty);

        var user = await _userService.FindByIdAsync(sub);
        if (user is null)
        {
            // Orphan token — revoke it and 401. See MeAsync for the rationale.
            await _tokenService.RevokeOrphanedTokenAsync(token, Request.GetRemoteIpAddress());
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.InvalidToken));
        }

        if (!await _userService.IsEmailConfirmedAsync(user))
        {
            // User exists but their email isn't confirmed. Anomalous (login already gates
            // on this) but don't revoke — the user may legitimately be in mid-flow if
            // some future feature changes their email and forces re-confirm.
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidRequest));
        }

        if (await _userService.IsLockedOutAsync(user))
        {
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, ErrorMessages.AccountLocked));
        }

        var resetResult = await _userService.ChangePasswordAsync(user, request.OldPassword!, request.NewPassword!);
        if (!resetResult.Succeeded)
        {
            var errors = resetResult.Errors.ToDictionary(e => e.Code, e => e.Description);
            return BadRequest(new ApiResponse().AddErrors(errors));
        }

        await _userService.InvalidateUserTokensAsync(user, Request.GetRemoteIpAddress(), RevocationReasons.PasswordChange, token);

        var lockoutToken = await _userService.GenerateUserTokenAsync(user, MfaProviders.Email.ToString(), TokenPurposes.Lockout);

        if (string.IsNullOrWhiteSpace(request.LockAccountUri))
        {
            request.LockAccountUri = $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.LockAccount}";
        }

        var lockAccountUri = AccountHelpers.GenerateLockoutUri(user.Email!, lockoutToken, request.LockAccountUri);

        await _emailService.SendEmailAsync(
            user.Email!,
            EmailSubjects.PasswordChanged,
            $"Your password was changed at {DateTime.UtcNow} UTC. If you didn't make this request please click the following link to lock your account and contact a system administrator. {lockAccountUri}");

        user.LockoutEnd = null;
        await _userService.UpdateAsync(user);

        await _userService.ResetAccessFailedCountAsync(user);

        _logger.LogInformation(
            SecurityEventIds.PasswordChanged,
            "Password changed for {UserId} from {IpAddress}",
            user.Id,
            Request.GetRemoteIpAddress());

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// "Wasn't me!" — the link in the password-changed email lands here. Locks the account
    /// and sends the real owner a password-reset email so they can recover it.
    /// </summary>
    [HttpPost("lock")]
    [EnableRateLimiting(RateLimitPolicies.AuthStrict)]
    public async Task<IActionResult> LockAccountAsync(LockAccountDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidRequest));
        }

        if (!await _userService.VerifyUserTokenAsync(user, MfaProviders.Email.ToString(), TokenPurposes.Lockout, request.Token!))
        {
            return Unauthorized(new ApiResponse().AddError(ResponseConstants.Unauthorized, "Token is not valid"));
        }

        await _userService.InvalidateUserTokensAsync(user, Request.GetRemoteIpAddress(), RevocationReasons.AccountLock);

        await _userService.SetLockoutEnabledAsync(user, true);
        await _userService.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);

        var token = await _userService.GeneratePasswordResetTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        if (string.IsNullOrWhiteSpace(request.ResetPasswordUri))
        {
            request.ResetPasswordUri = $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.ResetPassword}";
        }

        var resetPasswordUri = AccountHelpers.GenerateResetPasswordUri(user.Email!, encodedToken, request.ResetPasswordUri);

        await _emailService.SendEmailAsync(
            user.Email!,
            EmailSubjects.AccountLocked,
            $"Your account was locked at {DateTime.UtcNow} UTC. If you didn't make this request please contact a system administrator. To unlock your account you need to reset your password via the following link. {resetPasswordUri}");

        _logger.LogWarning(
            SecurityEventIds.AccountLockedByUser,
            "Account locked by user via email link for {UserId} from {IpAddress}",
            user.Id,
            Request.GetRemoteIpAddress());

        return Ok(new ApiResponse());
    }
}