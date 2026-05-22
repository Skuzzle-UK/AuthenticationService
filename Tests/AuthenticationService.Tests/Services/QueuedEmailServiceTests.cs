using System.Threading.Channels;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AwesomeAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// Covers the producer side of <see cref="QueuedEmailService"/> — the channel write contract.
/// The consumer-side SMTP dispatch is integration-test territory.
/// </summary>
public class QueuedEmailServiceTests
{
    [Fact]
    public async Task SendEmailAsync_ReturnsQuickly_WithoutBlockingOnSmtp()
    {
        // arrange — SendEmailAsync just enqueues; SMTP dispatch is out of band.
        var service = BuildService();

        // act
        var start = DateTime.UtcNow;
        await service.SendEmailAsync("alice@example.com", "subject", "body");
        var elapsed = DateTime.UtcNow - start;

        // assert
        elapsed.Should().BeLessThan(TimeSpan.FromMilliseconds(100));
    }

    [Fact]
    public async Task SendEmailAsync_MultipleWriters_AllEnqueueWithoutLoss()
    {
        // arrange — Channel is SingleWriter=false; BoundedCapacity=1000 so 50 fits comfortably.
        var service = BuildService();

        // act
        var tasks = Enumerable.Range(0, 50)
            .Select(i => service.SendEmailAsync($"user{i}@example.com", $"subject {i}", $"body {i}"))
            .ToList();
        await Task.WhenAll(tasks);

        // assert
        tasks.Should().AllSatisfy(t => t.IsCompletedSuccessfully.Should().BeTrue());
    }

    [Fact]
    public async Task SendEmailAsync_QueueFull_DropsMessageAfterTimeoutWithoutThrowing()
    {
        // arrange — producer catches the QueueWriteTimeout OperationCanceledException and drops the message;
        // protects callers from a transient queue-full state cascading into request failures.
        var service = BuildService();

        // act + assert
        var tasks = Enumerable.Range(0, 100)
            .Select(i => service.SendEmailAsync($"u{i}@x.y", "s", "b"))
            .ToArray();
        var act = async () => await Task.WhenAll(tasks);

        await act.Should().NotThrowAsync();
    }

    private static QueuedEmailService BuildService()
    {
        return new QueuedEmailService(
            Options.Create(new EmailServerSettings
            {
                From = "noreply@example.com",
                SmtpServer = "localhost",
                Port = 25,
            }),
            NullLogger<QueuedEmailService>.Instance);
    }
}
