namespace AuthenticationService.Constants;

/// <summary>
/// API route fragments referenced from outside the controller (e.g. email-link builders).
/// </summary>
public class ApiRoutes
{
    /// <summary>
    /// Path of the GET endpoint that completes email confirmation when the user clicks the link.
    /// </summary>
    public const string ConfirmEmail = "/confirm/email";
}