using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Profile fields the logged-in user can change via <c>PUT /api/Account/me</c>. Each field
/// is optional: send only the ones being changed and the rest are left untouched. Fields
/// not covered here have dedicated flows (username / email / password / MFA / roles).
///
/// <para>Changing <see cref="PhoneNumber"/> resets the phone-confirmed flag — the user must
/// re-confirm before SMS-based MFA works again, since the old confirmation no longer
/// applies to the new number.</para>
/// </summary>
public class UpdateProfileDto
{
    /// <summary>
    /// First (given) name. Null leaves the existing value alone; empty string clears it.
    /// </summary>
    [MaxLength(50)]
    public string? FirstName { get; set; }

    /// <summary>
    /// Last (family) name. Null leaves the existing value alone; empty string clears it.
    /// </summary>
    [MaxLength(50)]
    public string? LastName { get; set; }

    /// <summary>
    /// Date of birth. Null leaves the existing value alone.
    /// </summary>
    public DateOnly? DateOfBirth { get; set; }

    /// <summary>
    /// Phone number in any format the <see cref="PhoneAttribute"/> accepts. Changing this
    /// resets <c>PhoneNumberConfirmed</c> — the user must re-confirm before SMS-based MFA
    /// will work against the new number.
    /// </summary>
    [Phone]
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Country (free-text — no ISO-code validation here). Null leaves alone; empty clears.
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
