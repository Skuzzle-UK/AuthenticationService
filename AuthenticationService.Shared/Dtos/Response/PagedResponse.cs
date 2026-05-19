namespace AuthenticationService.Shared.Dtos.Response;

/// <summary>
/// Generic paged-list response. Wraps <see cref="Results"/> with the paging metadata the
/// client needs to render a paginator (total count + the page + size it asked for).
///
/// <para>Inherits <see cref="ApiResponse"/> so error reporting + <see cref="ApiResponse.IsSuccessful"/>
/// work the same as any other response. On a failed request, <c>Results</c> will be
/// empty and the errors dictionary will carry the reason.</para>
///
/// <para>First use is the admin user-list endpoint; Phase 1 reuses for the
/// client-management list endpoint.</para>
/// </summary>
/// <typeparam name="T">The list-item shape (typically a thin summary DTO).</typeparam>
public class PagedResponse<T> : ApiResponse
{
    /// <summary>The page of items the server returned (may be empty if past the last page).</summary>
    public IReadOnlyList<T> Results { get; set; } = [];

    /// <summary>Total matching rows ignoring paging — used by the client to compute the page count.</summary>
    public int TotalCount { get; set; }

    /// <summary>The 1-indexed page number the server returned (echoes the request's <c>page</c> param).</summary>
    public int Page { get; set; }

    /// <summary>The page size the server applied (may be clamped down from the request).</summary>
    public int PageSize { get; set; }
}
