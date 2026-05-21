using AuthenticationService.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Services;

/// <summary>
/// Façade over ASP.NET Core Identity's <c>UserManager</c>. Most methods are pass-throughs;
/// <see cref="InvalidateUserTokensAsync"/> composes the "log out everywhere" cascade.
/// </summary>
public interface IUserService
{
    Task<IdentityResult> CreateAsync(User user, string password);

    /// <summary>
    /// Creates a user with no password — admin-invitation flow. Caller can't authenticate until they accept the invite.
    /// </summary>
    Task<IdentityResult> CreateAsync(User user);

    /// <summary>
    /// Adds the user to a role. The role must already exist.
    /// </summary>
    Task AddToRoleAsync(User user, string role);

    /// <summary>
    /// Returns the role names the user belongs to.
    /// </summary>
    Task<IList<string>> GetRolesAsync(User user);

    /// <summary>
    /// Marks the user's email as confirmed if the supplied token is valid.
    /// </summary>
    Task<IdentityResult> ConfirmEmailAsync(User user, string token);

    /// <summary>
    /// Generates a single-use token to embed in the email-confirmation link.
    /// </summary>
    Task<string> GenerateEmailConfirmationTokenAsync(User user);

    /// <summary>
    /// Looks up a user by email address. Returns null if no such user exists.
    /// </summary>
    Task<User?> FindByEmailAsync(string email);

    /// <summary>
    /// Looks up a user by their stable id (the <c>sub</c> claim). Returns null if no such user exists.
    /// </summary>
    Task<User?> FindByIdAsync(string id);

    /// <summary>
    /// Returns the user's authenticator-app shared secret, or null if MFA isn't set up.
    /// </summary>
    Task<string?> GetAuthenticatorKeyAsync(User user);

    /// <summary>
    /// Generates a new authenticator-app secret, replacing any existing one.
    /// </summary>
    Task ResetAuthenticatorKeyAsync(User user);

    /// <summary>
    /// Returns the MFA token-provider names the user has enabled (e.g. <c>"Authenticator"</c>, <c>"Email"</c>).
    /// </summary>
    Task<IList<string>> GetValidMfaProvidersAsync(User user);

    /// <summary>
    /// True if the user has MFA enabled.
    /// </summary>
    Task<bool> GetMfaEnabledAsync(User user);

    /// <summary>
    /// Turns MFA on or off for the user.
    /// </summary>
    Task SetMfaEnabledAsync(User user, bool enabled);

    /// <summary>
    /// Persists changes to the user record.
    /// </summary>
    Task UpdateAsync(User user);

    /// <summary>
    /// True if the user has confirmed their email address.
    /// </summary>
    Task<bool> IsEmailConfirmedAsync(User user);

    /// <summary>
    /// Generates a single-use token to embed in the password-reset link.
    /// </summary>
    Task<string> GeneratePasswordResetTokenAsync(User user);

    /// <summary>
    /// Generates a single-use token for the given purpose using the named token provider.
    /// </summary>
    Task<string> GenerateUserTokenAsync(User user, string tokenProvider, string purpose);

    /// <summary>
    /// Generates an MFA challenge code (e.g. the 6-digit number sent over email).
    /// </summary>
    Task<string> GenerateMfaTokenAsync(User user, string tokenProvider);

    /// <summary>
    /// Resets the failed-login counter back to zero — typically after a successful login.
    /// </summary>
    Task ResetAccessFailedCountAsync(User user);

    /// <summary>
    /// Sets a new password using the single-use token from a password-reset email.
    /// </summary>
    Task<IdentityResult> ResetPasswordAsync(User user, string token, string newPassword);

    /// <summary>
    /// Changes the user's password while they're authenticated. Requires the current password.
    /// </summary>
    Task<IdentityResult> ChangePasswordAsync(User user, string currentPassword, string newPassword);

    /// <summary>
    /// Verifies a single-use token (email confirmation, password reset, lockout link).
    /// </summary>
    Task<bool> VerifyUserTokenAsync(User user, string tokenProvider, string purpose, string token);

    /// <summary>
    /// Verifies an MFA challenge code submitted by the user.
    /// </summary>
    Task<bool> VerifyMfaTokenAsync(User user, string tokenProvider, string token);

    /// <summary>
    /// Enables or disables Identity's lockout machinery for this specific user.
    /// </summary>
    Task SetLockoutEnabledAsync(User user, bool enabled);

    /// <summary>
    /// Sets the date the user's lockout expires (or null to clear it).
    /// </summary>
    Task SetLockoutEndDateAsync(User user, DateTimeOffset? endDate);

    /// <summary>
    /// True if the user is currently locked out.
    /// </summary>
    Task<bool> IsLockedOutAsync(User user);

    /// <summary>
    /// Verifies the password without bumping the failure counter.
    /// </summary>
    Task<bool> CheckPasswordAsync(User user, string password);

    /// <summary>
    /// Bumps the failed-login counter and triggers lockout once the limit is hit.
    /// </summary>
    Task AccessFailedAsync(User user);

    /// <summary>
    /// "Log this user out everywhere". Rotates the security stamp (invalidates Identity-issued
    /// tokens like password-reset and email-confirm links), revokes every refresh-token family,
    /// and — if <paramref name="token"/> is supplied — also revokes that access token.
    /// </summary>
    Task InvalidateUserTokensAsync(User user, string ipAddress, string reason, string? token = null);

    /// <summary>
    /// Rotates the security stamp — existing Identity tokens (reset, email-confirm, lockout, MFA)
    /// immediately stop validating. Used after consuming a single-use email link to prevent replay.
    /// </summary>
    Task UpdateSecurityStampAsync(User user);
}
