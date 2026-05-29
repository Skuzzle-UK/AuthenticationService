using AuthenticationService.Constants;

namespace AuthenticationService.Validators;

/// <summary>
/// Validates tenant names against the rules locked in Decision 6 of the multi-tenancy
/// plan: format regex, length, reserved-name rejection, no consecutive hyphens, no
/// pure-numeric values. Stateless — register as a singleton.
/// </summary>
public interface ITenantNameValidator
{
    /// <summary>
    /// Validate a tenant name. Returns null if valid; otherwise a human-readable
    /// rejection reason suitable for surfacing in a ValidationProblemDetails response.
    /// </summary>
    string? Validate(string? name);
}

public class TenantNameValidator : ITenantNameValidator
{
    private readonly HashSet<string> _reserved;

    public TenantNameValidator()
    {
        _reserved = new HashSet<string>(TenantConstants.ReservedNames, StringComparer.OrdinalIgnoreCase);
    }

    public string? Validate(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return "Name is required.";
        }

        // Length is part of the regex but a length-specific error message is friendlier.
        if (name.Length < TenantConstants.NameMinLength || name.Length > TenantConstants.NameMaxLength)
        {
            return $"Name must be between {TenantConstants.NameMinLength} and {TenantConstants.NameMaxLength} characters.";
        }

        if (!TenantConstants.NameRegex().IsMatch(name))
        {
            return "Name must be lowercase, start and end with a letter or digit, and contain only letters, digits, and hyphens.";
        }

        // Regex permits consecutive hyphens in the middle — reject those explicitly.
        if (name.Contains("--", StringComparison.Ordinal))
        {
            return "Name must not contain consecutive hyphens.";
        }

        // Pure-numeric names look like IDs in URLs and are confusing — reject.
        if (name.All(char.IsDigit))
        {
            return "Name must contain at least one letter.";
        }

        if (_reserved.Contains(name))
        {
            return "Name is reserved and can't be used.";
        }

        return null;
    }
}
