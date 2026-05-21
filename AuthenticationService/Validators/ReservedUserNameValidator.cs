using AuthenticationService.Entities;
using AuthenticationService.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Validators;

/// <summary>
/// Identity user-validator that blocks registrations matching a configured reserved-names deny-list (administrator, root, support, etc.) to prevent impersonation.
/// </summary>
public class ReservedUserNameValidator : IUserValidator<User>
{
    private readonly HashSet<string> _reservedNames;

    public ReservedUserNameValidator(IOptions<IdentitySettings> identitySettings)
    {
        _reservedNames = new HashSet<string>(
            identitySettings.Value.User.ReservedUserNames,
            StringComparer.OrdinalIgnoreCase);
    }

    public Task<IdentityResult> ValidateAsync(UserManager<User> manager, User user)
    {
        if (IsReserved(user.UserName))
        {
            return Task.FromResult(IdentityResult.Failed(new IdentityError
            {
                Code = "ReservedUserName",
                Description = "The chosen username is reserved. Please choose a different one.",
            }));
        }

        return Task.FromResult(IdentityResult.Success);
    }

    private bool IsReserved(string? userName) =>
        !string.IsNullOrWhiteSpace(userName) && _reservedNames.Contains(userName.Trim());
}
