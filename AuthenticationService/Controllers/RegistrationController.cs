using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Extensions;
using AuthenticationService.Observability;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.Text;

namespace AuthenticationService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class RegistrationController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly IEmailService _emailService;
    private readonly DatabaseContext _dbContext;
    private readonly PublicUrlSettings _publicUrlSettings;
    private readonly CorsSettings _corsSettings;
    private readonly ILogger<RegistrationController> _logger;
    private readonly AuthMetrics _metrics;

    public RegistrationController(
        IUserService userService,
        IEmailService emailService,
        DatabaseContext dbContext,
        IOptions<PublicUrlSettings> publicUrlSettings,
        IOptions<CorsSettings> corsSettings,
        ILogger<RegistrationController> logger,
        AuthMetrics metrics)
    {
        _userService = userService;
        _emailService = emailService;
        _dbContext = dbContext;
        _publicUrlSettings = publicUrlSettings.Value;
        _corsSettings = corsSettings.Value;
        _logger = logger;
        _metrics = metrics;
    }

    /// <summary>
    /// Creates a new user and emails them a confirmation link. The account can't log in until the link is clicked.
    /// </summary>
    [HttpPost("register")]
    [EnableRateLimiting(RateLimitPolicies.AuthStrict)]
    public async Task<IActionResult> RegisterUserAsync([FromBody] RegistrationDto request)
    {
        if (request is null)
        {
            return BadRequest();
        }

        var user = new User
        {
            UserName = request.UserName,
            FirstName = request.FirstName,
            LastName = request.LastName,
            DateOfBirth = request.DateOfBirth,
            Email = request.Email,
            PhoneNumber = request.PhoneNumber,
            Country = request.Country,
            AddressLine1 = request.AddressLine1,
            AddressLine2 = request.AddressLine2,
            AddressLine3 = request.AddressLine3,
            Postcode = request.Postcode,
            City = request.City,
        };

        // Manual transactions must be wrapped in a CreateExecutionStrategy call so the
        // retry strategy (MySqlRetryingExecutionStrategy) can retry the whole thing as one
        // unit on transient DB failures. Unhandled exceptions fall through to the
        // ProblemDetails handler in the pipeline (traceId is the correlation handle).
        var strategy = _dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync<IActionResult>(async () =>
        {
            using var transaction = await _dbContext.Database.BeginTransactionAsync();

            var result = await _userService.CreateAsync(user, request.Password!);
            if (!result.Succeeded)
            {
                var errors = result.Errors.ToDictionary(e => e.Code, e => e.Description);
                return BadRequest(new ApiResponse().AddErrors(errors));
            }

            if (request.PreferredMfaProvider is not null)
            {
                user.PreferredMfaProvider = request.PreferredMfaProvider.Value;
                await _userService.UpdateAsync(user);
            }

            await _userService.AddToRoleAsync(user, RolesConstants.DefaultUser);

            await SendConfirmEmailAsync(user, request.EmailConfirmationCallbackUri);

            await transaction.CommitAsync();

            _logger.LogInformation(
                SecurityEventIds.RegistrationCompleted,
                "Registration completed for {UserId}",
                user.Id);

            _metrics.RegistrationCompleted();

            return Created();
        });
    }

    /// <summary>
    /// Landing point for the registration confirmation link. Marks the email confirmed, rotates the security stamp so the link can't be reused, then redirects to <paramref name="callbackUri"/>.
    /// </summary>
    [HttpGet("confirm/email")]
    public async Task<IActionResult> ConfirmEmailAsync([FromQuery] string email, [FromQuery] string token, [FromQuery] string? callbackUri)
    {
        var user = await _userService.FindByEmailAsync(email);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidEmailConfirmationRequest));
        }

        var confirmationResult = await _userService.ConfirmEmailAsync(user, token);
        if (!confirmationResult.Succeeded)
        {
            _logger.LogWarning(
                SecurityEventIds.EmailConfirmationFailed,
                "Email confirmation failed for {UserId} from {IpAddress}",
                user.Id,
                Request.GetRemoteIpAddress());
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidEmailConfirmationRequest));
        }

        await _userService.UpdateSecurityStampAsync(user);

        _logger.LogInformation(
            SecurityEventIds.EmailConfirmed,
            "Email confirmed for {UserId}",
            user.Id);
        
        _metrics.EmailConfirmed();

        return Redirect(ResolveSafeCallback(callbackUri));
    }

    // Validates callbackUri against the CORS allow-list before honouring it.
    private string ResolveSafeCallback(string? callbackUri)
    {
        var defaultDestination = $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.ActionComplete}";

        if (string.IsNullOrWhiteSpace(callbackUri))
        {
            return defaultDestination;
        }

        if (IsAllowedRedirect(callbackUri))
        {
            return callbackUri;
        }

        _logger.LogWarning(
            "Rejected open-redirect attempt to {CallbackUri} from {IpAddress}; redirecting to default",
            callbackUri,
            Request.GetRemoteIpAddress());
        return defaultDestination;
    }

    private bool IsAllowedRedirect(string callbackUri)
    {
        // RelativeOrAbsolute + explicit IsAbsoluteUri check: UriKind.Absolute is platform-dependent
        // for "/..." paths — Linux parses them as file:// URIs, Windows correctly rejects. Bug only
        // shows up on CI (Linux) runners.
        if (!Uri.TryCreate(callbackUri, UriKind.RelativeOrAbsolute, out var uri) || !uri.IsAbsoluteUri)
        {
            return true; // relative URL — stays on our origin, safe
        }

        var origin = uri.GetLeftPart(UriPartial.Authority);
        return _corsSettings.AllowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Completes the admin-invite flow. Sets the password and confirms email in one step. Returns 400 invitation_invalid (unknown email or bad token — single shape so we don't leak which emails exist) or 409 invitation_already_used.
    /// </summary>
    [HttpPost("accept-invitation")]
    [EnableRateLimiting(RateLimitPolicies.AuthStrict)]
    public async Task<IActionResult> AcceptInvitationAsync([FromBody] AcceptInvitationDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError("invitation_invalid", ErrorMessages.InvalidRequest));
        }

        // Pending-invitation guard — email not confirmed AND no password set.
        if (user.EmailConfirmed || !string.IsNullOrEmpty(user.PasswordHash))
        {
            return Conflict(new ApiResponse().AddError(
                "invitation_already_used",
                "User has already activated their account; invitation no longer applies."));
        }

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token!));

        var resetResult = await _userService.ResetPasswordAsync(user, decodedToken, request.NewPassword!);
        if (!resetResult.Succeeded)
        {
            var errors = resetResult.Errors.ToDictionary(e => e.Code, e => e.Description);
            return BadRequest(new ApiResponse().AddErrors(errors));
        }

        user.EmailConfirmed = true;
        await _userService.UpdateAsync(user);

        _logger.LogInformation(
            SecurityEventIds.InvitationAccepted,
            "Invitation accepted by {UserId} from {IpAddress}",
            user.Id,
            Request.GetRemoteIpAddress());

        // Redirect-shape if a callback was supplied; otherwise standard 200.
        if (!string.IsNullOrWhiteSpace(request.CallbackUri))
        {
            return Ok(new { redirect = ResolveSafeCallback(request.CallbackUri) });
        }

        return Ok(new ApiResponse());
    }

    /// <summary>
    /// Resends the email-confirmation link. Returns 200 even for unknown emails — don't leak which addresses are registered.
    /// </summary>
    [HttpPost("confirm/email")]
    [EnableRateLimiting(RateLimitPolicies.AuthStrict)]
    public async Task<IActionResult> ResendConfirmEmailAsync([FromBody] ResendEmailConfirmationDto request)
    {
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, ErrorMessages.InvalidRequest));
        }

        if (await _userService.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError(ResponseConstants.BadRequest, "User email already confirmed"));
        }

        await SendConfirmEmailAsync(user, request.CallbackUri);

        return Ok(new ApiResponse());
    }

    private async Task SendConfirmEmailAsync(User user, string? callbackUri)
    {
        var controllerPath = $"/api/{ControllerContext.ActionDescriptor.ControllerName.ToLower()}";
        var confirmEmailPath = $"{_publicUrlSettings.BaseUrl}{controllerPath}{ApiRoutes.ConfirmEmail}";

        var token = await _userService.GenerateEmailConfirmationTokenAsync(user);

        var confirmEmailParams = new Dictionary<string, string>
        {
            { UriConstants.Token, token },
            { UriConstants.Email, user.Email! },
            // Fall back to the bundled ActionComplete page if no callback supplied.
            { UriConstants.CallBackUri, callbackUri ?? $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.ActionComplete}" }
        };

        var confirmEmailUri = QueryHelpers.AddQueryString(confirmEmailPath, confirmEmailParams!);

        await _emailService.SendEmailAsync(
            user.Email!,
            EmailSubjects.EmailConfirmation,
            $"To confirm your email address please click the following link: {confirmEmailUri}");
    }
}
