namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Generic paged-list response. Wraps <see cref="Results"/> with the paging metadata the
/// client needs to render a paginator.
/// </summary>
/// <typeparam name="T">The list-item shape (typically a thin summary DTO).</typeparam>
public class PagedResponse<T> : ApiResponse
{
    /// <summary>
    /// The page of items the server returned (may be empty if past the last page).
    /// </summary>
    public IReadOnlyList<T> Results { get; set; } = [];

    /// <summary>
    /// Total matching rows ignoring paging — used by the client to compute the page count.
    /// </summary>
    public int TotalCount { get; set; }

    /// <summary>
    /// The 1-indexed page number the server returned (echoes the request's <c>page</c> param).
    /// </summary>
    public int Page { get; set; }

    /// <summary>
    /// The page size the server applied (may be clamped down from the request).
    /// </summary>
    public int PageSize { get; set; }
}
