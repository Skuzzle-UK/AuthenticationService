using AuthenticationService.Settings;
using Microsoft.Extensions.Options;
using System.Net.Mail;
using System.Net;

namespace AuthenticationService.Services;

/// <summary>
/// SMTP-backed implementation of <see cref="IEmailService"/>. Reads server config from
/// <see cref="EmailServerSettings"/>, sends HTML emails over TLS, logs success and
/// rethrows on failure so the caller can react.
/// </summary>
public class EmailService : IEmailService
{
    private readonly EmailServerSettings _settings;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IOptions<EmailServerSettings> settings, ILogger<EmailService> logger)
    {
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task SendEmailAsync(string toEmail, string subject, string body)
    {
        var smtpClient = new SmtpClient(_settings.SmtpServer)
        {
            Port = _settings.Port,
            Credentials = new NetworkCredential(_settings.UserName, _settings.Password),
            EnableSsl = true,
        };

        var mailMessage = new MailMessage
        {
            From = new MailAddress(_settings.From),
            Subject = subject,
            Body = body,
            IsBodyHtml = true,
        };
        mailMessage.To.Add(toEmail);

        try
        {
            await smtpClient.SendMailAsync(mailMessage);

            _logger.LogInformation(
                "Sent email {Subject} to {Recipient}",
                subject,
                toEmail);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Failed to send email {Subject} to {Recipient} via {SmtpServer}:{SmtpPort}",
                subject,
                toEmail,
                _settings.SmtpServer,
                _settings.Port);
            throw;
        }
    }
}
