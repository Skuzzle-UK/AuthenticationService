namespace AuthenticationService.Services;

/// <summary>
/// Default <see cref="ISmsService"/> registration. Reports <see cref="IsConfigured"/> as
/// <c>false</c>; throws on send. Phone-MFA endpoints check <c>IsConfigured</c> first and
/// return a clear "not configured" error to clients rather than letting this throw.
///
/// <para>To enable phone MFA on a deployment, implement <see cref="ISmsService"/> against
/// a real SMS provider (Twilio, AWS SNS, MessageBird, etc.) and replace the registration
/// in <c>HostExtensions.AddServices</c>. Nothing in the controller code needs to change.</para>
/// </summary>
public sealed class SmsService : ISmsService
{
    public bool IsConfigured => false;

    public Task SendAsync(string phoneNumber, string message) =>
        throw new NotSupportedException(
            "SMS provider is not configured. Register a real ISmsService implementation in " +
            "HostExtensions.AddServices to enable phone MFA, or check ISmsService.IsConfigured " +
            "before calling SendAsync.");
}
