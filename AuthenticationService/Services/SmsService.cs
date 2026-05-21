namespace AuthenticationService.Services;

/// <summary>
/// Default <see cref="ISmsService"/> stub. Reports <c>IsConfigured = false</c> and throws on send.
/// Replace the registration in <c>HostExtensions.AddServices</c> with a real provider to enable phone MFA.
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
