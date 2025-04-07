using AuthenticationService.Entities;
using AuthenticationService.Services;
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

    public RegistrationController(
        IUserService userService,
        IEmailService emailService,
        IMapper mapper,
        DatabaseContext dbContext)
    {
        _userService = userService;
        _emailService = emailService;
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
            var result = await _userService.CreateAsync(user, request.Password!);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description);
                return BadRequest(new ApiResponse().AddErrors(errors));
            }

            if (request.Preferred2FAProvider is not null)
            {
                user.Preferred2FAProvider = request.Preferred2FAProvider.Value;
                await _userService.UpdateAsync(user);
            }

            await _userService.AddToRoleAsync(user, "User");

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
        var user = await _userService.FindByEmailAsync(email);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError("Invalid email confirmation request"));
        }

        var confirmationResult = await _userService.ConfirmEmailAsync(user, token);
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
        var user = await _userService.FindByEmailAsync(request.Email!);
        if (user is null)
        {
            return BadRequest(new ApiResponse().AddError("Invalid request"));
        }

        if (await _userService.IsEmailConfirmedAsync(user))
        {
            return BadRequest(new ApiResponse().AddError("User email already confirmed"));
        }

        await SendConfirmEmailAsync(user, request.CallbackUri);

        return Ok(new ApiResponse());
    }

    private async Task SendConfirmEmailAsync(User user, string? callbackUri)
    {
        var host = $"{Request.Scheme}://{Request.Host}";
        var controllerPath = $"/api/{ControllerContext.ActionDescriptor.ControllerName.ToLower()}";
        var confirmEmailPath = $"{host}{controllerPath}/confirm/email";

        var token = await _userService.GenerateEmailConfirmationTokenAsync(user);

        var confirmEmailParams = new Dictionary<string, string>
        {
            { "token", token },
            { "email", user.Email! },
            { "callbackUri", callbackUri ?? $"{Request.Scheme}://{Request.Host}{Request.PathBase}/confirm/email?callbackUri={{Request.Scheme}}://{{Request.Host}}{{Request.PathBase}}/ActionComplete" }
        };

        var confirmEmailUri = QueryHelpers.AddQueryString(confirmEmailPath, confirmEmailParams!);

        await _emailService.SendEmailAsync(
            user.Email!,
            "Email Confirmation",
            $"To confirm your email address please click the following link: {confirmEmailUri}");
    }
}
