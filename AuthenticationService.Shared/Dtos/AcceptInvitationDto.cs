using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Body for <c>POST /api/registration/accept-invitation</c>. Sets the password and confirms
/// the email in one round-trip; rejected if the account is already active.
/// </summary>
public class AcceptInvitationDto
{
    [Required(ErrorMessage = "Email is required."), EmailAddress]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Token is required.")]
    public string? Token { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    public string? NewPassword { get; set; }

    /// <summary>
    /// Optional redirect target after success. Validated against the open-redirect allow-list.
    /// </summary>
    public string? CallbackUri { get; set; }
}
