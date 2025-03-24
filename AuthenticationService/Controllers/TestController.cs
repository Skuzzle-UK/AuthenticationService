using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService.Controllers;
[Route("api/[controller]")]
[ApiController]
public class TestController : ControllerBase
{
    [HttpGet]
    [Authorize(Policy = "OnlyAdminUsers")]
    public IActionResult TestAdminOnlyAsync()
    {
        return Ok("Test succeeded");
    }

    [HttpGet("all")]
    [Authorize]
    public IActionResult TestAllAuthenticatedUsersAsync()
    {
        return Ok("Test succeeded");
    }
}
