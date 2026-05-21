using AuthenticationService.Services;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// Pins the default <see cref="ISmsService"/> stub returns IsConfigured=false and throws on send —
/// so future work registering a real provider does so by replacing the registration rather than extending this stub.
/// </summary>
public class SmsServiceTests
{
    [Fact]
    public void IsConfigured_DefaultImplementation_ReturnsFalse()
    {
        var sms = new SmsService();

        sms.IsConfigured.Should().BeFalse();
    }

    [Fact]
    public async Task SendAsync_DefaultImplementation_ThrowsNotSupported()
    {
        var sms = new SmsService();

        var act = async () => await sms.SendAsync("+1234567890", "test message");

        // Explicit failure — a silent no-op would mask MFA not being delivered in production.
        await act.Should().ThrowAsync<NotSupportedException>()
            .WithMessage("*not configured*");
    }
}
