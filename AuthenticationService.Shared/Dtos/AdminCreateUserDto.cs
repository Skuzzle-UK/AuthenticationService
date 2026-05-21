using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Body for <c>POST /api/Admin/users</c> — admin-creates-user invitation flow. No password
/// field: the user sets their own via the invitation link, which also confirms their email.
/// </summary>
public class AdminCreateUserDto
{
    [Required(ErrorMessage = "UserName is required."), MaxLength(50)]
    public string? UserName { get; set; }

    [Required(ErrorMessage = "Email is required."), EmailAddress]
    public string? Email { get; set; }

    [Required(ErrorMessage = "FirstName is required."), MaxLength(50)]
    public string? FirstName { get; set; }

    [Required(ErrorMessage = "LastName is required."), MaxLength(50)]
    public string? LastName { get; set; }

    [Phone]
    public string? PhoneNumber { get; set; }

    public DateOnly? DateOfBirth { get; set; }

    [MaxLength(60)]
    public string? Country { get; set; }

    [MaxLength(256)]
    public string? AddressLine1 { get; set; }

    [MaxLength(256)]
    public string? AddressLine2 { get; set; }

    [MaxLength(256)]
    public string? AddressLine3 { get; set; }

    [MaxLength(60)]
    public string? City { get; set; }

    [MaxLength(20)]
    public string? Postcode { get; set; }

    /// <summary>
    /// Roles to assign to the new user. Defaults to <c>DefaultUser</c> if omitted. Must not
    /// contain <c>Admin</c> — admin accounts are seeded via DB seed, not this endpoint.
    /// </summary>
    public IList<string>? Roles { get; set; }

    /// <summary>
    /// Optional. Redirect target after the user sets their password. Validated against the open-redirect allow-list.
    /// </summary>
    public string? CallbackUri { get; set; }
}
