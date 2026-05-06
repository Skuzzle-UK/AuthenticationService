namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Standard wrapper for API responses. <see cref="IsSuccessful"/> is true by default;
/// adding any error flips it to false. Subclasses (like <see cref="AuthenticationResponse"/>)
/// add domain-specific payload alongside this base shape.
/// </summary>
public class ApiResponse
{
    /// <summary>True until an error is added. Calling <see cref="Successful"/> flips it back.</summary>
    public bool IsSuccessful { get; private set; } = true;

    /// <summary>Keyed errors. Null when there are none.</summary>
    public Dictionary<string, string>? Errors { get; private set; }

    /// <summary>Adds one keyed error and marks the response unsuccessful. Returns <c>this</c> for chaining.</summary>
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

    /// <summary>Adds many keyed errors at once and marks the response unsuccessful. Returns <c>this</c> for chaining.</summary>
    public ApiResponse AddErrors(Dictionary<string, string> errors)
    {
        if (Errors == null)
        {
            Errors = new Dictionary<string, string>();
        }

        foreach (var kvp in errors)
        {
            Errors[kvp.Key] = kvp.Value;
        }

        IsSuccessful = false;

        return this;
    }

    /// <summary>
    /// Forces <see cref="IsSuccessful"/> back to true even if errors have been added.
    /// Used in the rare cases where errors are informational rather than fatal — call after
    /// all <c>AddError</c> calls.
    /// </summary>
    public ApiResponse Successful()
    {
        IsSuccessful = true;
        return this;
    }
}
