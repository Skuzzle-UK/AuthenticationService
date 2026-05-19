namespace AuthenticationService.Services;

/// <summary>
/// Filter shape for <c>IAdminService.ListUsersAsync</c>. The controller maps query-string
/// params into one of these so the service layer doesn't take a dependency on
/// ASP.NET model binding.
///
/// <para><see cref="Page"/> is 1-indexed. <see cref="PageSize"/> is clamped to
/// <see cref="MaxPageSize"/> by the controller (defence against client-driven DoS).</para>
/// </summary>
public sealed class AdminListFilter
{
    public const int MaxPageSize = 100;
    public const int DefaultPageSize = 20;

    public int Page { get; init; } = 1;
    public int PageSize { get; init; } = DefaultPageSize;

    /// <summary>
    /// Case-insensitive substring match against <c>UserName</c> OR <c>Email</c>. Null/empty = no filter.
    /// </summary>
    public string? Search { get; init; }

    /// <summary>
    /// When true, only users with <c>LockoutEnd &gt; UTC now</c>.
    /// </summary>
    public bool LockedOnly { get; init; }

    /// <summary>
    /// When true, only users with <c>EmailConfirmed = false</c>.
    /// </summary>
    public bool UnconfirmedOnly { get; init; }
}
