using AuthenticationService.Settings;
using Microsoft.Extensions.Options;
using System.Net.Mail;
using System.Net;

namespace AuthenticationService.Services;

public class EmailService : IEmailService
{
    private readonly EmailServiceSettings _settings;

    public EmailService(IOptions<EmailServiceSettings> settings)
    {
        _settings = settings.Value;
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

        await smtpClient.SendMailAsync(mailMessage);
    }
}
