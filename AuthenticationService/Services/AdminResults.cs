using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Services;

/// <summary>
/// Outcome of an admin-creates-user call. Discriminates the three negative paths the
/// controller has to map to distinct HTTP responses (400 for validation, 409 for
/// duplicate, 200 for happy) from a single service-layer return.
/// </summary>
public abstract record AdminCreateUserResult
{
    public sealed record Success(string UserId) : AdminCreateUserResult;

    /// <summary>
    /// Validation rejected the request (invalid role, missing field, etc.). <see cref="Errors"/> carries the dictionary the API surface returns.
    /// </summary>
    public sealed record ValidationFailed(IDictionary<string, string> Errors) : AdminCreateUserResult;

    /// <summary>
    /// Username or email already in use. Surfaced as 409 to distinguish from request-shape errors.
    /// </summary>
    public sealed record Conflict(string Reason) : AdminCreateUserResult;

    /// <summary>
    /// The role list referenced an unknown role. Bundled distinctly so the controller can return a 400 with a precise error.
    /// </summary>
    public sealed record UnknownRole(string RoleName) : AdminCreateUserResult;

    /// <summary>
    /// Identity itself rejected the create (password policy, custom validator, etc.). Surfaced as 400 with Identity's error dictionary.
    /// </summary>
    public sealed record IdentityFailed(IEnumerable<IdentityError> IdentityErrors) : AdminCreateUserResult;
}

/// <summary>
/// Outcome of a resend-invitation call. <c>NotFound</c> = no such user;
/// <c>AlreadyActive</c> = user has either confirmed their email or already set a
/// password, so the invitation flow no longer applies.
/// </summary>
public enum AdminInvitationResendResult
{
    Resent,
    UserNotFound,
    UserAlreadyActive
}
