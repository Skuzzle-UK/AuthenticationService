namespace AuthenticationService.Constants;

/// <summary>
/// User-facing error message strings returned in API responses. Centralised so the same
/// failure case shows the same text everywhere, and so future localisation has one place
/// to look up keys.
/// </summary>
public class ErrorMessages
{
    /// <summary>
    /// Generic "we couldn't process this request" — used when validation fails or required fields are missing.
    /// </summary>
    public const string InvalidRequest = "Invalid request.";

    /// <summary>
    /// The bearer token is missing, malformed, or otherwise unusable.
    /// </summary>
    public const string InvalidToken = "Token is invalid.";

    /// <summary>
    /// The supplied refresh token isn't recognised — never issued, already consumed, or belongs to a different user.
    /// </summary>
    public const string InvalidRefreshToken = "Refresh token is invalid.";

    /// <summary>
    /// The refresh token was real but has aged out past its expiry.
    /// </summary>
    public const string ExpiredRefreshToken = "Refresh token has expired.";

    /// <summary>
    /// Internal failure — a JWT we expected to contain a <c>jti</c> claim doesn't.
    /// </summary>
    public const string MissingJtiClaim = "Token does not contain a jti claim.";

    /// <summary>
    /// Generic "the account is locked" — used when locked but we don't want to leak why.
    /// </summary>
    public const string AccountLocked = "Your account is locked.";

    /// <summary>
    /// Specific lockout reason: too many wrong-password attempts. Auto-clears after the configured duration.
    /// </summary>
    public const string AccountLockedFailedAttempts = "Your account is locked due to too many failed login attempts.";

    /// <summary>
    /// The MFA provider supplied (Email / Phone / Authenticator) isn't enabled for this user, or isn't a recognised value.
    /// </summary>
    public const string InvalidMfaProvider = "Invalid MFA Provider.";

    /// <summary>
    /// Phone MFA was requested but no SMS provider is wired up on this deployment.
    /// </summary>
    public const string PhoneMfaNotConfigured = "Phone MFA is not configured on this deployment.";

    /// <summary>
    /// Phone MFA was requested but the user has no confirmed phone number on file.
    /// </summary>
    public const string PhoneNumberNotConfirmed = "Phone number is missing or not confirmed.";

    /// <summary>
    /// The email-confirmation link is malformed, expired, or for a non-existent user.
    /// </summary>
    public const string InvalidEmailConfirmationRequest = "Invalid email confirmation request";
}