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
        // arrange
        var sms = new SmsService();

        // act + assert
        sms.IsConfigured.Should().BeFalse();
    }

    [Fact]
    public async Task SendAsync_DefaultImplementation_ThrowsNotSupported()
    {
        // arrange
        var sms = new SmsService();

        // act + assert — explicit failure: a silent no-op would mask MFA not being delivered in production.
        var act = async () => await sms.SendAsync("+1234567890", "test message");

        await act.Should().ThrowAsync<NotSupportedException>()
            .WithMessage("*not configured*");
    }
}
