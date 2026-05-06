namespace AuthenticationService.Services;

/// <summary>
/// Sends outbound emails for the auth flows — registration confirmation, password reset,
/// MFA, account-lock notifications, and similar.
/// </summary>
public interface IEmailService
{
    /// <summary>
    /// Sends a single email. Subject and body are passed straight through.
    /// </summary>
    Task SendEmailAsync(string toEmail, string subject, string body);
}
