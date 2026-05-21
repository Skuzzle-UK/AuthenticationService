# Adding an endpoint

Practical walk-through for adding a new feature end-to-end. The recipe assembles the conventions in [conventions.md](conventions.md) into a concrete sequence.

## The shape

Most new features touch these files, in roughly this order:

1. **DTO** (request + response) in `AuthenticationService.Shared/Dtos/`
2. **Service interface + implementation** in `AuthenticationService/Services/`
3. **Controller action** in `AuthenticationService/Controllers/`
4. **Settings** (if any) in `AuthenticationService/Settings/`
5. **DI registration** in `AuthenticationService/Extensions/HostExtensions.cs`
6. **Unit tests** mirroring the source tree under `Tests/AuthenticationService.Tests/`
7. **Integration test** (only when the behaviour is cross-cutting / DB-shape-dependent)

Plus, for security-relevant features:

8. **`SecurityEventIds` entry** in `AuthenticationService/Constants/`
9. **`AuthMetrics` counter / gauge** in `AuthenticationService/Observability/`
10. **SIEM rule recommendation** added to [operations/observability.md](../operations/observability.md#siem-contract)

## Worked example: "admin disables a user"

Imagine adding an admin endpoint that disables (soft-deletes) a user account.

### 1. DTO

`AuthenticationService.Shared/Dtos/AdminDisableUserDto.cs`:

```csharp
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class AdminDisableUserDto
{
    /// <summary>
    /// Operator-supplied reason. Stored on the audit event so an investigator
    /// can read why this account was disabled six months later.
    /// </summary>
    [Required]
    [MaxLength(500)]
    public string Reason { get; set; } = default!;
}
```

Add a corresponding test file `Tests/AuthenticationService.Shared.Tests/Dtos/AdminDisableUserDtoTests.cs` pinning the `[Required]` + `[MaxLength]` annotations (drive `Validator.TryValidateObject`, assert names appear in `MemberNames`).

### 2. Service

Surface the operation on `IAdminService` and implement on `AdminService`:

```csharp
public interface IAdminService
{
    // ... existing methods ...

    /// <summary>
    /// Soft-disables the user. Effect: refresh families revoked, current access token
    /// added to the deny-list, security stamp rotated, lockout set to <see cref="LockoutDurations.Indefinite"/>.
    /// The user can be re-enabled by an admin via <c>UnlockUserAsync</c>.
    /// </summary>
    Task<AdminDisableUserResult> DisableUserAsync(
        string userId,
        string reason,
        string adminId,
        string ipAddress,
        CancellationToken ct);
}

public abstract record AdminDisableUserResult
{
    public sealed record Success : AdminDisableUserResult;
    public sealed record UserNotFound : AdminDisableUserResult;
    public sealed record CannotDisableSelf : AdminDisableUserResult;   // self-protection
}
```

The **discriminated-union return** is a recurring pattern. It forces controller code to handle every outcome explicitly via pattern matching, instead of relying on exceptions for flow control.

Implement with the existing collaborators (`UserManager<User>`, `ITokenService`, `IEmailService`). Log via `_logger.LogWarning(SecurityEventIds.AdminDisabledAccount, ...)` and increment `_metrics.AccountDisabled()`.

### 3. Controller

In `AdminController.cs`:

```csharp
[HttpPost("users/{userId}/disable")]
[ProducesResponseType(StatusCodes.Status204NoContent)]
[ProducesResponseType(StatusCodes.Status400BadRequest)]
[ProducesResponseType(StatusCodes.Status404NotFound)]
public async Task<IActionResult> DisableUserAsync(
    [FromRoute] string userId,
    [FromBody] AdminDisableUserDto dto,
    CancellationToken ct)
{
    var adminId = User.FindFirstValue(ClaimConstants.Sub)!;
    var ip = HttpContext.GetRemoteIpAddress();

    var result = await _adminService.DisableUserAsync(userId, dto.Reason, adminId, ip, ct);

    return result switch
    {
        AdminDisableUserResult.Success            => NoContent(),
        AdminDisableUserResult.UserNotFound       => NotFound(),
        AdminDisableUserResult.CannotDisableSelf  => BadRequest(new { error = "cannot_disable_self" }),
        _ => throw new InvalidOperationException($"Unhandled result: {result.GetType().Name}"),
    };
}
```

The `_ => throw` arm catches future expansion — if a new `AdminDisableUserResult` variant is added without updating the controller, the throw makes the gap visible in tests immediately.

### 4. Settings — not needed in this example

If the feature needed tunables (e.g. "auto-re-enable after X days"), they'd go in a new `*Settings` class with `[Required]` / `[Range]` annotations + a settings test fixture.

### 5. DI registration

`AdminService` is already registered in `HostExtensions.AddServices`. No new wiring.

### 6. Unit tests

Mirror the source structure: `Tests/AuthenticationService.Tests/Services/AdminServiceTests.cs` gets new tests for each `AdminDisableUserResult` variant; `Tests/AuthenticationService.Tests/Controllers/AdminControllerTests.cs` gets tests that the switch-expression maps each variant to the right HTTP shape.

Use the existing `BuildService` helper (SQLite InMemory + substituted collaborators) and follow the **arrange / act / assert with `why` comments** pattern.

### 7. Integration test — only if needed

For "admin disables a user," scenario coverage probably belongs in the existing admin-lifecycle test rather than a new scenario file. If you do add one:

- Live as a class under `AuthenticationService.IntegrationTests/Scenarios/`.
- Use `[Collection(IntegrationTestCollection.Name)]` so it shares the AppHost fixture.
- Drive everything via `AuthClient` (Aspire-injected HttpClient at the auth service's URL).
- Assert against MySQL directly via `await using var db = await CreateDbContextAsync()` when the DB shape matters.

See [`AuthenticationService.IntegrationTests/Scenarios/AdminInvitationFlowTests.cs`](../../AuthenticationService.IntegrationTests/Scenarios/AdminInvitationFlowTests.cs) for the closest existing pattern.

### 8. SecurityEventIds entry

`AuthenticationService/Constants/SecurityEventIds.cs` gets:

```csharp
public static readonly EventId AdminDisabledAccount = new(5008, nameof(AdminDisabledAccount));
```

…with a comment explaining what the event signals (so the SIEM rule author can write the right detection).

### 9. AuthMetrics counter

`AuthenticationService/Observability/AuthMetrics.cs` gets:

```csharp
public void AccountDisabled() => _accountDisabledCounter.Add(1);

// ... in the constructor ...
_accountDisabledCounter = _meter.CreateCounter<long>(
    "auth.accounts.disabled.total",
    description: "Admin-driven account disable events.");
```

### 10. SIEM rule recommendation

Update [operations/observability.md](../operations/observability.md#siem-contract) — typically not page-worthy on its own, but a `GROUP BY adminId` query is useful for spotting admin abuse patterns.

## Recipe checklist

For your next endpoint:

- [ ] DTO with DataAnnotations + DTO test fixture
- [ ] Service method on interface + impl, with discriminated-union return for non-trivial outcomes
- [ ] Controller action with pattern-match dispatch + ProducesResponseType attributes for OpenAPI
- [ ] Settings class (if tunable) + settings test fixture
- [ ] DI registration (if a new service)
- [ ] Unit tests mirroring source structure, arrange/act/assert + why comments
- [ ] Integration test only if cross-cutting / DB-shape-dependent
- [ ] SecurityEventIds entry for security-relevant events
- [ ] AuthMetrics counter / gauge for observability-relevant events
- [ ] SIEM rule recommendation if useful
- [ ] XML docs on public surface
- [ ] No magic strings — use constants from `AuthenticationService.Shared.Constants`

## See also

- [development/conventions.md](conventions.md) — the conventions referenced above
- [development/testing.md](testing.md) — running tests + per-project coverage
