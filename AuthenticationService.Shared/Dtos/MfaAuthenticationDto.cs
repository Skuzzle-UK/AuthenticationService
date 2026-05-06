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
    /// Optional. Where to send the user if they get locked out by too many failed MFA
    /// attempts and want to reset their password proactively. See
    /// <see cref="AuthenticationDto.ResetPasswordUri"/> for the same field's description on
    /// the login DTO.
    /// </summary>
    public string? ResetPasswordUri { get; set; }
}
