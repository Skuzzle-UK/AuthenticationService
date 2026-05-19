using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Body for <c>POST /api/registration/accept-invitation</c> — the form submission from
/// the AcceptInvitation page after an admin-created user clicks the link in their
/// invitation email.
///
/// <para>One round-trip sets the password AND marks the email confirmed. The token is
/// an Identity password-reset token generated when the admin created the user; the
/// pending-invitation check (<c>!EmailConfirmed &amp;&amp; PasswordHash IS NULL</c>) makes
/// sure this endpoint can't be used to reset the password of an already-active user.</para>
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
    /// Optional redirect target after success. Validated against the open-redirect
    /// allow-list before honouring.
    /// </summary>
    public string? CallbackUri { get; set; }
}
