using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Controllers;

/// <summary>
/// Controller for testing out authentication/authorization scenarios
/// </summary>
[Route("api/[controller]")]
[ApiController]
public class TestController : ControllerBase
{
    /// <summary>
    /// A test endpoint locked down to only admin
    /// </summary>
    /// <returns>Ok if successful auth else returns 401</returns>
    [HttpGet]
    [Authorize(Policy = PolicyConstants.AdminOnly)]
    public IActionResult TestAdminOnlyAsync()
    {
        return Ok("Test succeeded");
    }

    /// <summary>
    /// A test endpoint for all authenticated users
    /// </summary>
    /// <returns>Ok if user token is valid and authenticated else returns 401</returns>
    [HttpGet("all")]
    [Authorize]
    public IActionResult TestAllAuthenticatedUsersAsync()
    {
        return Ok("Test succeeded");
    }
}
