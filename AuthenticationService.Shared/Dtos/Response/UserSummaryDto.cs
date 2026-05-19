namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Thin user shape returned from the admin user-list endpoint. Deliberately small — full
/// detail (address, MFA provider, roles, active session count) comes from the dedicated
/// detail endpoint to keep list payloads cheap when an admin is paging through thousands
/// of users.
/// </summary>
public class UserSummaryDto
{
    public string Id { get; set; } = default!;

    public string UserName { get; set; } = default!;

    public string Email { get; set; } = default!;

    public bool EmailConfirmed { get; set; }

    /// <summary>Computed: <c>LockoutEnd &gt; UTC now</c>. False when the user has no lockout set.</summary>
    public bool IsLocked { get; set; }

    /// <summary>Reflects <c>TwoFactorEnabled</c> — not the running count of MFA-enabled users.</summary>
    public bool MfaEnabled { get; set; }

    public DateTime CreatedAt { get; set; }
}
