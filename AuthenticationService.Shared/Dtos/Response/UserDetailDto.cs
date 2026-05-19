namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Full user detail returned from <c>GET /api/Admin/users/{id}</c>. Combines the IdentityUser
/// fields (Id / UserName / Email / phone / lockout / MFA) with the profile fields the user
/// can edit themselves (name, DoB, address) plus a couple of computed aggregates
/// (<see cref="Roles"/>, <see cref="ActiveRefreshTokenFamilies"/>) admins commonly need.
///
/// <para>Deliberately excludes security stamp / password hash / JWT internals — those are
/// not auditable from this surface.</para>
/// </summary>
public class UserDetailDto : ApiResponse
{
    public string Id { get; set; } = default!;

    public string UserName { get; set; } = default!;

    public string Email { get; set; } = default!;

    public bool EmailConfirmed { get; set; }

    public string? FirstName { get; set; }

    public string? LastName { get; set; }

    public DateOnly? DateOfBirth { get; set; }

    public string? PhoneNumber { get; set; }

    public bool PhoneNumberConfirmed { get; set; }

    public string? Country { get; set; }

    public string? AddressLine1 { get; set; }

    public string? AddressLine2 { get; set; }

    public string? AddressLine3 { get; set; }

    public string? City { get; set; }

    public string? Postcode { get; set; }

    public LockoutInfoDto Lockout { get; set; } = new();

    public MfaInfoDto Mfa { get; set; } = new();

    public IList<string> Roles { get; set; } = [];

    /// <summary>
    /// Count of currently-live refresh-token families for the user — proxies "how many
    /// devices is this user signed in on right now."
    /// </summary>
    public int ActiveRefreshTokenFamilies { get; set; }

    public DateTime CreatedAt { get; set; }
}
