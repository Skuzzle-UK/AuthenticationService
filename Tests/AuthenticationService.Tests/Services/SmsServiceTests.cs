using AuthenticationService.Services;
using AwesomeAssertions;

namespace AuthenticationService.Tests.Services;

/// <summary>
/// <para>The default SMS service is a deliberately-not-implemented placeholder. The
/// AuthenticationController checks <see cref="ISmsService.IsConfigured"/> before calling
/// SMS-MFA paths and returns a clear error to clients if false. This test pins the
/// default behaviour so future work that registers a real SMS provider does so by
/// replacing the registration (rather than mistakenly extending this stub, which would
/// silently change the controller's "not configured" branch to "throws on send").</para>
/// </summary>
public class SmsServiceTests
{
    [Fact]
    public void IsConfigured_DefaultImplementation_ReturnsFalse()
    {
        // arrange / act
        var sms = new SmsService();

        // assert — controllers branch on this. Returning true here would make them try
        // SendAsync and hit the NotSupportedException at runtime instead of returning a
        // clean "phone MFA not configured" error to the client.
        sms.IsConfigured.Should().BeFalse();
    }

    [Fact]
    public async Task SendAsync_DefaultImplementation_ThrowsNotSupported()
    {
        // arrange
        var sms = new SmsService();

        // act
        var act = async () => await sms.SendAsync("+1234567890", "test message");

        // assert — explicit failure with a message that points operators at how to fix
        // it (register a real provider). Pinned because a silent no-op would mask "MFA
        // not actually being delivered" in production.
        await act.Should().ThrowAsync<NotSupportedException>()
            .WithMessage("*not configured*");
    }
}
