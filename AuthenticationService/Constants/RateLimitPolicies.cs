namespace AuthenticationService.Constants;

/// <summary>
/// Named rate-limit policies registered in <c>HostExtensions.AddRateLimiting</c>. Endpoints
/// tagged with a named policy are subject to BOTH the global limiter and the named policy —
/// most-restrictive wins.
/// </summary>
public static class RateLimitPolicies
{
    /// <summary>
    /// Per-IP cap for unauthenticated credential endpoints (10/min). Credential-stuffing defence.
    /// </summary>
    public const string AuthStrict = "auth-strict";

    /// <summary>
    /// Per-user cap for authenticated state-changing endpoints (10/min). Discourages hijacked-session abuse.
    /// </summary>
    public const string AuthSensitive = "auth-sensitive";
}
