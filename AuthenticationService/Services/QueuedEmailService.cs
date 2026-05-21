using AuthenticationService.Settings;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using System.Threading.Channels;

namespace AuthenticationService.Services;

/// <summary>
/// SMTP-backed <see cref="IEmailService"/>. <c>SendEmailAsync</c> returns as soon as the message
/// is queued; a background loop drains the queue and does the SMTP work off the request path.
/// </summary>
public sealed class QueuedEmailService : BackgroundService, IEmailService
{
    private const int QueueCapacity = 1000;
    private static readonly TimeSpan QueueWriteTimeout = TimeSpan.FromSeconds(1);

    private readonly EmailServerSettings _settings;
    private readonly ILogger<QueuedEmailService> _logger;
    private readonly Channel<EmailMessage> _queue;

    public QueuedEmailService(
        IOptions<EmailServerSettings> settings,
        ILogger<QueuedEmailService> logger)
    {
        _settings = settings.Value;
        _logger = logger;
        _queue = Channel.CreateBounded<EmailMessage>(new BoundedChannelOptions(QueueCapacity)
        {
            // Producer waits up to QueueWriteTimeout for space before WriteAsync's
            // CancellationToken trips — the producer catches and drops.
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
        });
    }

    /// <summary>
    /// Queues an email for background dispatch. Returns as soon as the message is on the
    /// queue; SMTP send happens asynchronously off the request thread.
    /// </summary>
    public async Task SendEmailAsync(string toEmail, string subject, string body)
    {
        using var cts = new CancellationTokenSource(QueueWriteTimeout);
        var message = new EmailMessage(toEmail, subject, body);

        try
        {
            await _queue.Writer.WriteAsync(message, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Queue full usually means SMTP is failing and the dispatcher can't keep up.
            _logger.LogError(
                "Email queue full for {QueueWriteTimeout}; dropping message {Subject} to {Recipient}. " +
                "Investigate SMTP health.",
                QueueWriteTimeout,
                subject,
                toEmail);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation(
            "Email dispatcher started. Queue capacity {QueueCapacity}, SMTP {SmtpServer}:{Port}.",
            QueueCapacity,
            _settings.SmtpServer,
            _settings.Port);

        SmtpClient? client = null;

        try
        {
            await foreach (var message in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                client = await DispatchAsync(message, client, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during shutdown.
        }
        finally
        {
            await ShutdownAsync(client);
            _queue.Writer.TryComplete();
            _logger.LogInformation("Email dispatcher stopped.");
        }
    }

    // Sends one queued message and returns the (possibly re-created) client for reuse on the
    // next iteration. SMTP send failures are logged but not propagated — the loop continues.
    private async Task<SmtpClient?> DispatchAsync(
        EmailMessage message,
        SmtpClient? client,
        CancellationToken cancellationToken)
    {
        try
        {
            client = await EnsureConnectedAsync(client, cancellationToken);

            var mimeMessage = BuildMimeMessage(message);
            await client.SendAsync(mimeMessage, cancellationToken);

            _logger.LogInformation(
                "Sent email {Subject} to {Recipient}",
                message.Subject,
                message.ToEmail);

            return client;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(
                ex,
                "Failed to send email {Subject} to {Recipient} via {SmtpServer}:{SmtpPort}",
                message.Subject,
                message.ToEmail,
                _settings.SmtpServer,
                _settings.Port);

            // Connection might be in a bad state — drop it and reconnect on the next message.
            await TryDisconnectAsync(client);
            return null;
        }
    }

    private async Task<SmtpClient> EnsureConnectedAsync(SmtpClient? client, CancellationToken cancellationToken)
    {
        if (client?.IsConnected == true && client.IsAuthenticated)
        {
            return client;
        }

        // Stale or never-connected client — start fresh.
        await TryDisconnectAsync(client);
        client?.Dispose();

        var fresh = new SmtpClient();
        await fresh.ConnectAsync(
            _settings.SmtpServer,
            _settings.Port,
            SecureSocketOptions.StartTlsWhenAvailable,
            cancellationToken);

        if (!string.IsNullOrEmpty(_settings.UserName))
        {
            await fresh.AuthenticateAsync(_settings.UserName, _settings.Password ?? string.Empty, cancellationToken);
        }

        return fresh;
    }

    private MimeMessage BuildMimeMessage(EmailMessage message)
    {
        var mime = new MimeMessage();
        mime.From.Add(MailboxAddress.Parse(_settings.From));
        mime.To.Add(MailboxAddress.Parse(message.ToEmail));
        mime.Subject = message.Subject;
        mime.Body = new TextPart("html") { Text = message.Body };
        return mime;
    }

    private async Task ShutdownAsync(SmtpClient? client)
    {
        if (client is null)
        {
            return;
        }

        try
        {
            if (client.IsConnected)
            {
                // QUIT properly so the server doesn't see this as a mid-session disconnect.
                // Fresh CancellationToken because stoppingToken is already cancelled here.
                using var disconnectCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await client.DisconnectAsync(quit: true, disconnectCts.Token);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Failed to cleanly disconnect SMTP client during shutdown. Connection will be torn down by process exit.");
        }
        finally
        {
            client.Dispose();
        }
    }

    private async Task TryDisconnectAsync(SmtpClient? client)
    {
        if (client?.IsConnected != true)
        {
            return;
        }

        try
        {
            using var disconnectCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await client.DisconnectAsync(quit: true, disconnectCts.Token);
        }
        catch
        {
            // Best-effort — we're about to drop the client anyway.
        }
    }

    private sealed record EmailMessage(string ToEmail, string Subject, string Body);
}
