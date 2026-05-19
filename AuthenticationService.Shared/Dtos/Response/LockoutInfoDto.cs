namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Lockout sub-record used by <see cref="UserDetailDto"/> and as the response shape from
/// the lock / unlock admin endpoints (so the client can verify the new state in one round
/// trip).
/// </summary>
public class LockoutInfoDto
{
    /// <summary>True iff <see cref="LockoutEnd"/> is in the future relative to UTC now.</summary>
    public bool IsLocked { get; set; }

    /// <summary>Wall-clock end of the active lockout window. Null when not locked.</summary>
    public DateTimeOffset? LockoutEnd { get; set; }

    /// <summary>Identity's count of consecutive failed sign-in attempts since the last reset.</summary>
    public int AccessFailedCount { get; set; }

    /// <summary>Identity's per-user enable flag — distinct from <see cref="IsLocked"/>. False means lockout never engages for this user.</summary>
    public bool LockoutEnabled { get; set; }
}
