namespace AuthenticationService.Constants;

/// <summary>
/// Sentinel values used when setting <c>User.LockoutEnd</c>. Centralised so the
/// "indefinite lockout" definition is consistent across the panic-button (account
/// /lock) endpoint and the threshold-escalation worker.
/// </summary>
public static class LockoutDurations
{
    /// <summary>
    /// Lockout end value used for indefinite (panic-button + threshold-escalation)
    /// locks. Effectively "forever" — a year that won't be reached in any operational
    /// timescale.
    ///
    /// <para>Why not <see cref="DateTimeOffset.MaxValue"/>? <c>MaxValue</c>'s fractional-
    /// second precision (.9999999 ticks) rounds up past <c>9999-12-31 23:59:59</c> when
    /// EF persists it to MySQL's <c>DATETIME(6)</c> column, triggering a "datetime field
    /// overflow" error on insert. Truncating to a clean <c>9999-12-31T00:00:00Z</c>
    /// stays inside MySQL's range while preserving the "lock forever" semantics —
    /// recovery is still gated on the password-reset flow regardless of the precise
    /// lockout end timestamp.</para>
    /// </summary>
    public static readonly DateTimeOffset Indefinite = new(9999, 12, 31, 0, 0, 0, TimeSpan.Zero);
}
