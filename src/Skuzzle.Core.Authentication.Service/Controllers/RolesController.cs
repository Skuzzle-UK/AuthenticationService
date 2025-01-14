using Microsoft.AspNetCore.Mvc;

namespace Skuzzle.Core.Authentication.Service.Controllers;

[Route("api/[controller]")]
[ApiController]
public class RolesController : ControllerBase
{
    // TODO: Finish this. Should require authentication by an admin to update here /nb
    // Will need to have Migration in place to set basic roles and configure a basic admin account before this will work.
}
