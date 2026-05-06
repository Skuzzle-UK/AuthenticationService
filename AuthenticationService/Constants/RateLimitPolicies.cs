namespace AuthenticationService.Constants;

/// <summary>
/// Names for the endpoint-scoped rate-limit policies registered in
/// <c>HostExtensions.AddRateLimiting</c>. Apply with
/// <c>[EnableRateLimiting(RateLimitPolicies.AuthStrict)]</c> on actions where the
/// global default isn't tight enough. Endpoints with a named policy attached are
/// subject to BOTH the global limiter and the named policy — most-restrictive wins.
/// </summary>
public static class RateLimitPolicies
{
    /// <summary>
    /// Per-IP cap for unauthenticated credential / link-handling endpoints
    /// (login, MFA, password reset request/confirm, registration, email-confirm).
    /// Sized for credential-stuffing defence — well above what a real user would do,
    /// well below what an attacker needs (10/minute per IP).
    /// </summary>
    public const string AuthStrict = "auth-strict";

    /// <summary>
    /// Per-user cap for authenticated state-changing endpoints (change password,
    /// lock account, enable MFA). Tighter than the global default to discourage abuse
    /// of a hijacked session (10/minute per user).
    /// </summary>
    public const string AuthSensitive = "auth-sensitive";
}
