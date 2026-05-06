using AuthenticationService.Shared.Enums;

namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Response from <c>GET /api/Account/me</c>. The current snapshot of the authenticated
/// user's profile + roles, read live from the database — so values are always current,
/// not whatever was stamped into the JWT at issue time.
///
/// <para>Two main consumers: SPAs that want to render "Hi {FirstName}" without parsing
/// the JWT, and developers debugging "is my token actually any good?" via Swagger.</para>
///
/// <para>Deliberately excludes internal Identity state (lockout counters, security stamp,
/// password hash) and token claims (<c>jti</c> / <c>sid</c> / <c>exp</c> — the client
/// already has the JWT and can decode those itself).</para>
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
