namespace AuthenticationService.Services;

/// <summary>
/// Filter shape for the admin audit endpoint. Pagination is 1-indexed.
/// </summary>
public sealed class AdminAuditFilter
{
    public const int MaxPageSize = 100;
    public const int DefaultPageSize = 50;

    public required string UserId { get; init; }
    public int Page { get; init; } = 1;
    public int PageSize { get; init; } = DefaultPageSize;

    /// <summary>
    /// Only events with <c>Timestamp &gt;= Since</c>. Controller defaults to last 30 days.
    /// </summary>
    public DateTimeOffset? Since { get; init; }

    /// <summary>
    /// Optional single-event filter. Null = all events.
    /// </summary>
    public int? EventId { get; init; }
}
