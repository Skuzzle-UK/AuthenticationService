namespace AuthenticationService.Services;

/// <summary>
/// Discriminated-union result from <see cref="ITenantService.CreateAsync"/>. Mirrors the
/// existing <c>AdminCreateUserResult</c> shape.
/// </summary>
public abstract record CreateTenantResult
{
    public sealed record Success(string TenantId, string Name) : CreateTenantResult;
    public sealed record InvalidName(string Reason) : CreateTenantResult;
    public sealed record NameAlreadyExists : CreateTenantResult;
}

/// <summary>
/// Result from the suspend / unsuspend / soft-delete / force-delete endpoints.
/// </summary>
public abstract record TenantLifecycleResult
{
    public sealed record Success : TenantLifecycleResult;
    public sealed record NotFound : TenantLifecycleResult;
    public sealed record InvalidStateTransition(string CurrentStatus) : TenantLifecycleResult;
    public sealed record ConfirmationMismatch : TenantLifecycleResult;
}
