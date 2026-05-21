namespace AuthenticationService.Enums;

/// <summary>
/// Why a login was rejected. Logged as <c>{Reason}</c> on <c>SecurityEventIds.LoginFailed</c>
/// so SIEM can distinguish wrong-password from account-state failures.
/// </summary>
public enum LoginFailureReason
{
    BadCredentials,
    AccountLocked,
    EmailNotConfirmed
}
