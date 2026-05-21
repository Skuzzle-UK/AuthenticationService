using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Profile fields the logged-in user can change via <c>PUT /api/Account/me</c>. Each field
/// is optional: null leaves the existing value alone, empty string clears it.
/// </summary>
public class UpdateProfileDto
{
    /// <summary>
    /// First (given) name.
    /// </summary>
    [MaxLength(50)]
    public string? FirstName { get; set; }

    /// <summary>
    /// Last (family) name.
    /// </summary>
    [MaxLength(50)]
    public string? LastName { get; set; }

    /// <summary>
    /// Date of birth.
    /// </summary>
    public DateOnly? DateOfBirth { get; set; }

    /// <summary>
    /// Phone number. Changing this resets <c>PhoneNumberConfirmed</c> — the user must
    /// re-confirm before SMS-based MFA works against the new number.
    /// </summary>
    [Phone]
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Country (free-text — no ISO-code validation).
    /// </summary>
    [MaxLength(60)]
    public string? Country { get; set; }

    /// <summary>
    /// First line of the postal address.
    /// </summary>
    [MaxLength(256)]
    public string? AddressLine1 { get; set; }

    /// <summary>
    /// Second line of the postal address.
    /// </summary>
    [MaxLength(256)]
    public string? AddressLine2 { get; set; }

    /// <summary>
    /// Third line of the postal address.
    /// </summary>
    [MaxLength(256)]
    public string? AddressLine3 { get; set; }

    /// <summary>
    /// City / town.
    /// </summary>
    [MaxLength(60)]
    public string? City { get; set; }

    /// <summary>
    /// Postal / ZIP code.
    /// </summary>
    [MaxLength(20)]
    public string? Postcode { get; set; }
}
