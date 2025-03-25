#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Settings;

public class EmailServerSettings
{
    [Required, EmailAddress]
    public string From { get; set; }

    [Required]
    public string SmtpServer { get; set; }

    [Required]
    public int Port { get; set; }

    public string? UserName { get; set; }

    public string? Password { get; set; }
}
