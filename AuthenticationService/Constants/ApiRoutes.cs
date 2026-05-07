namespace AuthenticationService.Constants;

/// <summary>
/// Route fragments for API endpoints that need to be referenced from outside the
/// controller (e.g. when building email-confirmation links). Controller-only routes stay
/// inline as <c>[HttpGet("…")]</c> attributes — these constants exist for the routes that
/// are also referenced from email-link builders or similar.
/// </summary>
public class ApiRoutes
{
    /// <summary>
    /// Path of the GET endpoint that completes email confirmation when the user clicks the link.
    /// </summary>
    public const string ConfirmEmail = "/confirm/email";
}