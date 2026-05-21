#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

/// <summary>
/// SMTP server config for outbound auth emails.
/// </summary>
public class EmailServerSettings
{
    /// <summary>
    /// The address that appears in the From: header of outbound emails.
    /// </summary>
    [Required, EmailAddress]
    public string From { get; set; }

    /// <summary>
    /// SMTP server hostname.
    /// </summary>
    [Required]
    public string SmtpServer { get; set; }

    /// <summary>
    /// 587 STARTTLS, 465 implicit TLS, 25 plain.
    /// </summary>
    [Required]
    public int Port { get; set; }

    /// <summary>
    /// SMTP username, if the server requires authentication.
    /// </summary>
    public string? UserName { get; set; }

    /// <summary>
    /// SMTP password, if the server requires authentication.
    /// </summary>
    public string? Password { get; set; }
}
