namespace AuthenticationService.Services;

/// <summary>
/// Sends SMS messages — the integration point for phone MFA. Operator-provisioned: the
/// default registration in <c>HostExtensions.AddServices</c> is
/// <see cref="SmsService"/>, which reports <see cref="IsConfigured"/> as
/// <c>false</c> and throws on send. To enable phone MFA on a deployment, replace that
/// registration with a real provider implementation (Twilio, AWS SNS, MessageBird, etc.).
/// The MFA endpoints check <see cref="IsConfigured"/> before calling
/// <see cref="SendAsync"/> and return a clear <c>BadRequest</c> when phone MFA is selected
/// against a deployment that doesn't have a provider wired.
/// </summary>
public interface ISmsService
{
    /// <summary>
    /// True when a real SMS provider is registered. Phone-MFA endpoints gate on this so
    /// the controller never calls <see cref="SendAsync"/> against the not-configured stub.
    /// </summary>
    bool IsConfigured { get; }

    /// <summary>
    /// Sends an SMS to the given phone number. Throws <see cref="NotSupportedException"/>
    /// if no provider is configured — callers should check <see cref="IsConfigured"/> first.
    /// </summary>
    Task SendAsync(string phoneNumber, string message);
}
