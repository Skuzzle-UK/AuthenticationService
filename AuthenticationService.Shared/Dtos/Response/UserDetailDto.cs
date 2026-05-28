namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Full user detail returned from <c>GET /api/Admin/users/{id}</c>. Combines IdentityUser
/// fields, editable profile fields, and computed aggregates (roles, active session count).
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
    /// Count of live refresh-token families — proxies "how many devices is this user signed in on."
    /// </summary>
    public int ActiveRefreshTokenFamilies { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}
