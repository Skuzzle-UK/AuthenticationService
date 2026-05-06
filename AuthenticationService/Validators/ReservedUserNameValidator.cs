using AuthenticationService.Constants;
using AuthenticationService.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Validators;

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