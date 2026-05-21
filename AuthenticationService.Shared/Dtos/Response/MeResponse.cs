using AuthenticationService.Shared.Enums;

namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Response from <c>GET /api/Account/me</c> — live snapshot of the authenticated user's
/// profile + roles (read from the database, not the JWT).
/// </summary>
public class MeResponse : ApiResponse
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

    public bool MfaEnabled { get; set; }

    public MfaProviders PreferredMfaProvider { get; set; }

    public IList<string> Roles { get; set; } = [];
}
