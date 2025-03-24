using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Entities;

public class Role : IdentityRole
{
    public string? Description { get; set; }
}
