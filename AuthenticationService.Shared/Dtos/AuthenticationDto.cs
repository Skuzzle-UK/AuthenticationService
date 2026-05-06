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
    /// Optional. Where to send the user if they get locked out by too many failed login
    /// attempts and want to reset their password proactively. Multi-consumer setups should
    /// pass their own UI's reset URL here; if omitted, the auth service falls back to its
    /// own bundled <c>/ResetPassword</c> page on <c>PublicUrlSettings.BaseUrl</c>.
    /// </summary>
    public string? ResetPasswordUri { get; set; }
}
