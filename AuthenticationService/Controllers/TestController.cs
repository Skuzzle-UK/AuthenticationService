using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Controllers;

/// <summary>
/// Test endpoints for verifying auth/authz wiring.
/// </summary>
[Route("api/[controller]")]
[ApiController]
public class TestController : ControllerBase
{
    /// <summary>
    /// Admin-only test endpoint.
    /// </summary>
    [HttpGet]
    [Authorize(Policy = PolicyConstants.AdminOnly)]
    public IActionResult TestAdminOnlyAsync()
    {
        return Ok("Test succeeded");
    }

    /// <summary>
    /// Any-authenticated-user test endpoint.
    /// </summary>
    [HttpGet("all")]
    [Authorize]
    public IActionResult TestAllAuthenticatedUsersAsync()
    {
        return Ok("Test succeeded");
    }
}
