namespace AuthenticationService.Shared.Dtos.Response;

public class ApiResponse
{
    // All responses are successful by default.
    public bool IsSuccessful { get; private set; } = true;

    public Dictionary<string, string>? Errors { get; private set; }

    /// <summary>
    /// Add a single error string to the response.
    /// </summary>
    /// <param name="error">string</param>
    public ApiResponse AddError(string key, string error)
    {
        if (Errors == null)
        {
            Errors = new Dictionary<string, string>();
        }

        Errors.Add(key, error);

        IsSuccessful = false;

        return this;
    }

    /// <summary>
    /// Add multiple error strings to the response.
    /// </summary>
    /// <param name="errors">IEnumerable<string></param>
    public ApiResponse AddErrors(Dictionary<string, string> errors)
    {
        if (Errors == null)
        {
            Errors = new Dictionary<string, string>();
        }

        Errors.Concat(errors);

        IsSuccessful = false;

        return this;
    }

    /// <summary>
    /// Allows override of response with errors so that it can still be successful but with errors.
    /// Must be called after all errors are added.
    /// </summary>
    public ApiResponse Successful()
    {
        IsSuccessful = true;
        return this;
    }
}
