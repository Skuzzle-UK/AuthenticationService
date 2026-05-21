namespace AuthenticationService.Constants;

/// <summary>
/// Sentinel <c>User.LockoutEnd</c> values shared by the panic-button endpoint and the
/// threshold-escalation worker.
/// </summary>
public static class LockoutDurations
{
    /// <summary>
    /// "Lock forever" sentinel. Not <see cref="DateTimeOffset.MaxValue"/> because its
    /// fractional ticks overflow MySQL's <c>DATETIME(6)</c> column on insert.
    /// </summary>
    public static readonly DateTimeOffset Indefinite = new(9999, 12, 31, 0, 0, 0, TimeSpan.Zero);
}
