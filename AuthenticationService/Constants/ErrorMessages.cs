namespace AuthenticationService.Constants;

public class ErrorMessages
{
    public const string InvalidRequest = "Invalid request.";
    public const string InvalidToken = "Token is invalid.";
    public const string InvalidRefreshToken = "Refresh token is invalid.";
    public const string ExpiredRefreshToken = "Refresh token has expired.";
    public const string MissingJtiClaim = "Token does not contain a jti claim.";
    public const string AccountLocked = "Your account is locked.";
    public const string AccountLockedFailedAttempts = "Your account is locked due to too many failed login attempts.";
    public const string InvalidMfaProvider = "Invalid MFA Provider.";
    public const string PhoneMfaNotConfigured = "Phone MFA is not configured on this deployment.";
    public const string PhoneNumberNotConfirmed = "Phone number is missing or not confirmed.";
    public const string InvalidEmailConfirmationRequest = "Invalid email confirmation request";
}
