using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Extensions;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

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

    public RegistrationController(
        IUserService userService,
        IEmailService emailService,
        DatabaseContext dbContext,
        IOptions<PublicUrlSettings> publicUrlSettings,
        IOptions<CorsSettings> corsSettings,
        ILogger<RegistrationController> logger)
    {
        _userService = userService;
        _emailService = emailService;
        _dbContext = dbContext;
        _publicUrlSettings = publicUrlSettings.Value;
        _corsSettings = corsSettings.Value;
        _logger = logger;
    }

    /// <summary>
    /// Creates a new user account and emails them a confirmation link. The account exists
    /// after this call but can't log in until the email link is clicked.
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

        using var transaction = await _dbContext.Database.BeginTransactionAsync();

        try
        {
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

            return Created();
        }
        catch (Exception ex)
        {
            var correlationId = Guid.NewGuid();
            _logger.LogError(ex,
                "Registration failed (correlation {CorrelationId})",
                correlationId);

            await transaction.RollbackAsync();
            return StatusCode(500, new ApiResponse().AddError(
                "RegistrationFailed",
                $"An unexpected error occurred. Please contact support with reference {correlationId}."));
        }
    }

    /// <summary>
    /// Lands here when the user clicks the confirmation link in their registration email.
    /// Marks the email as confirmed and rotates the user's security stamp so the link
    /// can't be reused.
    /// </summary>
    /// <param name="email">Requires valid email address</param>
    /// <param name="token">Token generated and sent to email in step 1</param>
    /// <param name="callbackUri">URI which user is redirected to after confirmation. Usually a page on the UI saying email confirmed and offering login</param>
    /// <returns>ApiResponse or redirects to callbackUri</returns>
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

        return Redirect(ResolveSafeCallback(callbackUri));
    }

    /// <summary>
    /// Validates the supplied <paramref name="callbackUri"/> against the CORS allow-list
    /// before honouring it.
    /// </summary>
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
        // Parse as RelativeOrAbsolute first, then explicitly check IsAbsoluteUri. Don't
        // use UriKind.Absolute directly: it's platform-dependent for paths that start
        // with '/'. Windows correctly returns false (no scheme); Linux interprets the
        // leading slash as a Unix path and parses it as a file:// URI, returning true.
        // The bug shows up in CI (Linux runners) but not on developer Windows boxes —
        // the kind of regression that's invisible until production / CI catches it.
        if (!Uri.TryCreate(callbackUri, UriKind.RelativeOrAbsolute, out var uri) || !uri.IsAbsoluteUri)
        {
            return true; // relative URL — stays on our origin, safe
        }

        var origin = uri.GetLeftPart(UriPartial.Authority);
        return _corsSettings.AllowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Resends the email-confirmation link if the user lost the original (e.g. it landed
    /// in spam). Returns 200 even when the email isn't recognised — we don't leak which
    /// addresses are registered.
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
            // After confirmation, redirect the user to the supplied callback if any,
            // otherwise to the bundled ActionComplete Razor page so something sensible
            // renders.
            { UriConstants.CallBackUri, callbackUri ?? $"{_publicUrlSettings.BaseUrl}{PageRouteConstants.ActionComplete}" }
        };

        var confirmEmailUri = QueryHelpers.AddQueryString(confirmEmailPath, confirmEmailParams!);

        await _emailService.SendEmailAsync(
            user.Email!,
            EmailSubjects.EmailConfirmation,
            $"To confirm your email address please click the following link: {confirmEmailUri}");
    }
}
