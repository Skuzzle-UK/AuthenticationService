using AuthenticationService.Shared.Enums;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class AuthenticationDto
{
    [Required(ErrorMessage = "Email is required.")]
    public string? Email { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    public string? Password { get; set; }

    public MfaProviders? MfaProvider { get; set; }

    /// <summary>
    /// Optional. Reset-password URL the user is sent to if they get locked out; falls back
    /// to the auth service's bundled <c>/ResetPassword</c> page when omitted.
    /// </summary>
    public string? ResetPasswordUri { get; set; }
}
