using AuthenticationService.Constants;
using AuthenticationService.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Validators;

/// <summary>
/// Plugged into Identity's user-validator chain to block registrations against a deny-list
/// of reserved names (<c>admin</c>, <c>root</c>, <c>support</c>, etc.) that could be used
/// to impersonate or phish. Runs automatically on <c>UserManager.CreateAsync</c>; the
/// allow-list is in <see cref="ReservedUserNames"/>.
/// </summary>
public class ReservedUserNameValidator : IUserValidator<User>
{
    public Task<IdentityResult> ValidateAsync(UserManager<User> manager, User user)
    {
        if (ReservedUserNames.IsReserved(user.UserName))
        {
            return Task.FromResult(IdentityResult.Failed(new IdentityError
            {
                Code = "ReservedUserName",
                Description = "The chosen username is reserved. Please choose a different one.",
            }));
        }

        return Task.FromResult(IdentityResult.Success);
    }
}