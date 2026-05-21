namespace AuthenticationService.Services;

/// <summary>
/// Sends SMS messages — the integration point for phone MFA. Operator-provisioned: the
/// default <see cref="SmsService"/> stub returns <see cref="IsConfigured"/> as <c>false</c>
/// and throws on send. Replace the registration in <c>HostExtensions.AddServices</c> with
/// a real provider (Twilio, AWS SNS, etc.) to enable phone MFA.
/// </summary>
public interface ISmsService
{
    /// <summary>
    /// True when a real SMS provider is registered. MFA endpoints gate on this before calling <see cref="SendAsync"/>.
    /// </summary>
    bool IsConfigured { get; }

    /// <summary>
    /// Throws <see cref="NotSupportedException"/> if no provider is configured — check <see cref="IsConfigured"/> first.
    /// </summary>
    Task SendAsync(string phoneNumber, string message);
}
