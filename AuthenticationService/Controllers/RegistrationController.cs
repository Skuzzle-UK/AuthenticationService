using AuthenticationService.Constants;
using AuthenticationService.Entities;
using AuthenticationService.Extensions;
using AuthenticationService.Services;
using AuthenticationService.Shared.Constants;
using AuthenticationService.Shared.Dtos;
using AuthenticationService.Shared.Dtos.Response;
using AuthenticationService.Storage;
using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace AuthenticationService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class RegistrationController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly IEmailService _emailService;
    private readonly IMapper _mapper;
    private readonly DatabaseContext _dbContext;
    private readonly ILogger<RegistrationController> _logger;

    public RegistrationController(
        IUserService userService,
        IEmailService emailService,
        IMapper mapper,
        DatabaseContext dbContext,
        ILogger<RegistrationController> logger)
    {
        _userService = userService;
        _emailService = emailService;
        _mapper = mapper;
        _dbContext = dbContext;
        _logger = logger;
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
            var result = await _userService.CreateAsync(user, request.Password!);
            if (!result.Succeeded)
            {
                var errors = result.Errors.ToDictionary(e => e.Code, e => e.Description);
                return BadRequest(new ApiResponse().AddErrors(errors));
            }

            if (request.Preferred2FAProvider is not null)
            {
                user.Preferred2FAProvider = request.Preferred2FAProvider.Value;
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
        var host = $"{Request.Scheme}://{Request.Host}";
        var controllerPath = $"/api/{ControllerContext.ActionDescriptor.ControllerName.ToLower()}";
        var confirmEmailPath = $"{host}{controllerPath}{ApiRoutes.ConfirmEmail}";

        var token = await _userService.GenerateEmailConfirmationTokenAsync(user);

        var confirmEmailParams = new Dictionary<string, string>
        {
            { UriConstants.Token, token },
            { UriConstants.Email, user.Email! },
            { UriConstants.CallBackUri, callbackUri ?? $"{Request.Scheme}://{Request.Host}{Request.PathBase}{ApiRoutes.ConfirmEmail}?callbackUri={{Request.Scheme}}://{{Request.Host}}{{Request.PathBase}}{RouteConstants.ActionComplete}" }
        };

        var confirmEmailUri = QueryHelpers.AddQueryString(confirmEmailPath, confirmEmailParams!);

        await _emailService.SendEmailAsync(
            user.Email!,
            EmailSubjects.EmailConfirmation,
            $"To confirm your email address please click the following link: {confirmEmailUri}");
    }
}
