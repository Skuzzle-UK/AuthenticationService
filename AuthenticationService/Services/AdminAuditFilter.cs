namespace AuthenticationService.Services;

/// <summary>
/// Filter shape for the admin audit endpoint. Mirrors the controller's query params one
/// for one. <see cref="UserId"/> is the target user; pagination is 1-indexed.
/// </summary>
public sealed class AdminAuditFilter
{
    public const int MaxPageSize = 100;
    public const int DefaultPageSize = 50;

    public required string UserId { get; init; }
    public int Page { get; init; } = 1;
    public int PageSize { get; init; } = DefaultPageSize;

    /// <summary>
    /// Only events with <c>Timestamp &gt;= Since</c>. Defaults to "last 30 days" on the controller side.
    /// </summary>
    public DateTime? Since { get; init; }

    /// <summary>
    /// Optional single-event filter. Null = all events.
    /// </summary>
    public int? EventId { get; init; }
}
