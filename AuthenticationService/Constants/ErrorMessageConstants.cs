namespace AuthenticationService.Constants;

public class ErrorMessageConstants
{
    public const string InvalidRequest = "Invalid request";
    public const string AccountLocked = "Your account is locked.";
    public const string AccountLockedFailedAttempts = "Your account is locked due to too many failed login attempts.";
    public const string InvalidMfaProvider = "Invalid MFA Provider";
    public const string PhoneMfaNotSupported = "Phone MFA is not supported yet.";
    public const string InvalidEmailConfirmationRequest = "Invalid email confirmation request";
}
