using AuthenticationService.Entities;
using AuthenticationService.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Validators;

/// <summary>
/// Plugged into Identity's user-validator chain to block registrations against a deny-list
/// of reserved names (<c>administrator</c>, <c>root</c>, <c>support</c>, etc.) that could
/// be used to impersonate or phish. Runs automatically on <c>UserManager.CreateAsync</c>;
/// the deny-list comes from <see cref="UserSettings.ReservedUserNames"/> in
/// <see cref="IdentitySettings"/> and is operator-extensible via configuration.
/// </summary>
public class ReservedUserNameValidator : IUserValidator<User>
{
    private readonly HashSet<string> _reservedNames;

    public ReservedUserNameValidator(IOptions<IdentitySettings> identitySettings)
    {
        // Snapshot the configured list into a HashSet for O(1) lookups + case-insensitive comparison.
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
