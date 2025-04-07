using AuthenticationService.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Services;

public interface IUserService
{
    Task<IdentityResult> CreateAsync(User user, string password);
    Task AddToRoleAsync(User user, string role);
    Task<IList<string>> GetRolesAsync(User user);
    Task<IdentityResult> ConfirmEmailAsync(User user, string token);
    Task<string> GenerateEmailConfirmationTokenAsync(User user);
    Task<User?> FindByNameAsync(string userName);
    Task<User?> FindByEmailAsync(string email);
    Task<string?> GetAuthenticatorKeyAsync(User user);
    Task ResetAuthenticatorKeyAsync(User user);
    Task<IList<string>> GetValidTwoFactorProvidersAsync(User user);
    Task<bool> GetTwoFactorEnabledAsync(User user);
    Task SetTwoFactorEnabledAsync(User user, bool enabled);
    Task UpdateAsync(User user);
    Task<bool> IsEmailConfirmedAsync(User user);
    Task<string> GeneratePasswordResetTokenAsync(User user);
    Task<string> GenerateUserTokenAsync(User user, string tokenProvider, string purpose);
    Task<string> GenerateTwoFactorTokenAsync(User user, string tokenProvider);
    Task ResetAccessFailedCountAsync(User user);
    Task<IdentityResult> ResetPasswordAsync(User user, string token, string newPassword);
    Task<IdentityResult> ChangePasswordAsync(User user, string currentPassword, string newPassword);
    Task<bool> VerifyUserTokenAsync(User user, string tokenProvider, string purpose, string token);
    Task<bool> VerifyTwoFactorTokenAsync(User user, string tokenProvider, string token);
    Task SetLockoutEnabledAsync(User user, bool enabled);
    Task SetLockoutEndDateAsync(User user, DateTimeOffset? endDate);
    Task<bool> IsLockedOutAsync(User user);
    Task<bool> CheckPasswordAsync(User user, string password);
    Task AccessFailedAsync(User user);
    Task InvalidateUserTokensAsync(User user, string ipAddress, string? token = null);
    bool VerifyRecoverAccountValues(
        User user, string? userName, string? firstName, string? lastName, DateOnly? dateOfBirth, string? email,
        string? phoneNumber, string? Country, string? mothersMaidenName, string? addressLine1, string? addressLine2,
        string? addressLine3, string? postcode, string? city);
}
