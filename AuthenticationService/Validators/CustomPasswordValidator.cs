using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Validators;

/// <summary>
/// Plugged into Identity's password-validator chain to reject passwords that match the
/// user's own username or email — a common dictionary-attack starting point. Identity's
/// built-in length / complexity rules still apply on top.
/// </summary>
public class CustomPasswordValidator<TUser> : IPasswordValidator<TUser> where TUser : class
{
    public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string? password)
    {
        var username = await manager.GetUserNameAsync(user);
        if (string.Equals(username, password, StringComparison.OrdinalIgnoreCase))
        {
            return IdentityResult.Failed(new IdentityError
            {
                Description = "Username and Password can not be the same.",
                Code = "SameUserPass"
            });
        }

        var email = await manager.GetEmailAsync(user);
        if (string.Equals(email, password, StringComparison.OrdinalIgnoreCase))
        {
            return IdentityResult.Failed(new IdentityError
            {
                Description = "Email and Password can not be the same.",
                Code = "SameEmailPass"
            });
        }

        return IdentityResult.Success;
    }
}
