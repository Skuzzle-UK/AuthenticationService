using AuthenticationService.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Services;

public class UserService : IUserService
{
    private readonly UserManager<User> _userManager;
    private readonly ITokenService _tokenService;

    public UserService(
        UserManager<User> userManager,
        ITokenService tokenService)
    {
        _userManager = userManager;
        _tokenService = tokenService;
    }

    public async Task AccessFailedAsync(User user) =>
        await _userManager.AccessFailedAsync(user);

    public async Task AddToRoleAsync(User user, string role) =>
        await _userManager.AddToRoleAsync(user, role);

    public async Task<IdentityResult> ChangePasswordAsync(User user, string currentPassword, string newPassword) =>
        await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);

    public async Task<bool> CheckPasswordAsync(User user, string password) =>
        await _userManager.CheckPasswordAsync(user, password);

    public async Task<IdentityResult> ConfirmEmailAsync(User user, string token) =>
        await _userManager.ConfirmEmailAsync(user, token);

    public async Task<IdentityResult> CreateAsync(User user, string password) =>
        await _userManager.CreateAsync(user, password);

    public async Task<User?> FindByEmailAsync(string email) =>
        await _userManager.FindByEmailAsync(email);

    public async Task<User?> FindByNameAsync(string userName) =>
        await (_userManager.FindByNameAsync(userName));

    public async Task<string> GenerateEmailConfirmationTokenAsync(User user) =>
        await _userManager.GenerateEmailConfirmationTokenAsync(user);

    public async Task<string> GeneratePasswordResetTokenAsync(User user) =>
        await _userManager.GeneratePasswordResetTokenAsync(user);

    public async Task<string> GenerateTwoFactorTokenAsync(User user, string tokenProvider) =>
        await _userManager.GenerateTwoFactorTokenAsync(user, tokenProvider);

    public async Task<string> GenerateUserTokenAsync(User user, string tokenProvider, string purpose) =>
        await _userManager.GenerateUserTokenAsync(user, tokenProvider, purpose);

    public async Task<string?> GetAuthenticatorKeyAsync(User user) =>
        await _userManager.GetAuthenticatorKeyAsync(user);

    public async Task<IList<string>> GetRolesAsync(User user) =>
        await _userManager.GetRolesAsync(user);

    public async Task<bool> GetTwoFactorEnabledAsync(User user) =>
        await _userManager.GetTwoFactorEnabledAsync(user);

    public async Task<IList<string>> GetValidTwoFactorProvidersAsync(User user) =>
        await _userManager.GetValidTwoFactorProvidersAsync(user);

    public async Task InvalidateUserTokensAsync(User user, string ipAddress, string? token = null)
    {
        await _userManager.UpdateSecurityStampAsync(user);
        user.RefreshToken = null;
        user.RefreshTokenExpiresAt = DateTime.MinValue;
        await _userManager.UpdateAsync(user);

        if (!string.IsNullOrEmpty(token))
        {
            await _tokenService.RevokeTokenAsync(token, ipAddress);
        }
    }

    public async Task<bool> IsEmailConfirmedAsync(User user) =>
        await _userManager.IsEmailConfirmedAsync(user);

    public async Task<bool> IsLockedOutAsync(User user) =>
        await _userManager.IsLockedOutAsync(user);

    public async Task ResetAccessFailedCountAsync(User user) =>
        await _userManager.ResetAccessFailedCountAsync(user);

    public async Task ResetAuthenticatorKeyAsync(User user) =>
        await _userManager.ResetAuthenticatorKeyAsync(user);

    public async Task<IdentityResult> ResetPasswordAsync(User user, string token, string newPassword) =>
        await _userManager.ResetPasswordAsync(user, token, newPassword);

    public async Task SetLockoutEnabledAsync(User user, bool enabled) =>
        await _userManager.SetLockoutEnabledAsync(user, enabled);

    public async Task SetLockoutEndDateAsync(User user, DateTimeOffset? endDate) =>
        await _userManager.SetLockoutEndDateAsync(user, endDate);

    public async Task SetTwoFactorEnabledAsync(User user, bool enabled) =>
        await _userManager.SetTwoFactorEnabledAsync(user, enabled);

    public async Task UpdateAsync(User user) =>
        await _userManager.UpdateAsync(user);

    public async Task<bool> VerifyTwoFactorTokenAsync(User user, string tokenProvider, string token) =>
        await _userManager.VerifyTwoFactorTokenAsync(user, tokenProvider, token);

    public async Task<bool> VerifyUserTokenAsync(User user, string tokenProvider, string purpose, string token) =>
        await _userManager.VerifyUserTokenAsync(user, tokenProvider, purpose, token);
}
