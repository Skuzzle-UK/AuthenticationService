using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Services;

/// <summary>
/// Outcome of an admin-creates-user call. Discriminates the negative paths the controller
/// maps to distinct HTTP responses (400 / 409 / 200).
/// </summary>
public abstract record AdminCreateUserResult
{
    public sealed record Success(string UserId) : AdminCreateUserResult;

    /// <summary>
    /// Validation rejected the request (invalid role, missing field, etc.). <see cref="Errors"/> carries the dictionary the API surface returns.
    /// </summary>
    public sealed record ValidationFailed(IDictionary<string, string> Errors) : AdminCreateUserResult;

    /// <summary>
    /// Username or email already in use — 409.
    /// </summary>
    public sealed record Conflict(string Reason) : AdminCreateUserResult;

    /// <summary>
    /// The role list referenced an unknown role. Bundled distinctly so the controller can return a 400 with a precise error.
    /// </summary>
    public sealed record UnknownRole(string RoleName) : AdminCreateUserResult;

    /// <summary>
    /// Identity rejected the create (password policy, custom validator, etc.).
    /// </summary>
    public sealed record IdentityFailed(IEnumerable<IdentityError> IdentityErrors) : AdminCreateUserResult;
}

/// <summary>
/// Outcome of a resend-invitation call. <c>AlreadyActive</c> means the user has confirmed
/// their email or set a password, so the invitation flow no longer applies.
/// </summary>
public enum AdminInvitationResendResult
{
    Resent,
    UserNotFound,
    UserAlreadyActive
}
