using AuthenticationService.Shared.Enums;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class MfaAuthenticationDto
{
    [Required(ErrorMessage = "Email is required.")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "MfaProvider is required.")]
    public MfaProviders? MfaProvider { get; set; }

    [Required(ErrorMessage = "Token is required.")]
    public string? Token { get; set; }

    /// <summary>
    /// Optional. Reset-password URL the user is sent to if they get locked out by too
    /// many failed MFA attempts.
    /// </summary>
    public string? ResetPasswordUri { get; set; }
}
