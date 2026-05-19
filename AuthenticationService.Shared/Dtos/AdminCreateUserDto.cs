using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

/// <summary>
/// Body for <c>POST /api/Admin/users</c> — the admin-creates-user invitation flow.
///
/// <para>No password field. The new account is created with <c>EmailConfirmed = false</c>
/// and no password hash; an invitation email goes to the supplied address with a link
/// that lands the user on the AcceptInvitation page to set their own password. The
/// password they set also confirms their email in the same step.</para>
///
/// <para><see cref="Roles"/> must not include <c>Admin</c>. Admin accounts are seeded
/// via DB seed, not via this endpoint — defence in depth against an admin escalating
/// themselves into a second admin via the API.</para>
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
    /// Roles to assign to the new user. Defaults to <c>DefaultUser</c> if omitted or empty.
    /// Must not contain <c>Admin</c>.
    /// </summary>
    public IList<string>? Roles { get; set; }

    /// <summary>
    /// Optional. Where to redirect the user after they successfully set their password.
    /// Validated against the open-redirect allow-list before honouring.
    /// </summary>
    public string? CallbackUri { get; set; }
}
