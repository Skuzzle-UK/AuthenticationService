# Code conventions

The conventions that aren't enforced by analyzers but shape every file in this repo. Following them keeps the codebase legible to the next person who has to read it cold.

## Comment why, not what

The single biggest convention: **comments explain reasoning, not mechanics.**

Bad — the code already says this:
```csharp
// Increment the counter
counter++;
```

Good — the code does NOT say this:
```csharp
// Increment after the DB write, not before — if SaveChanges throws, we don't want a
// metric showing a successful registration that never persisted.
counter++;
```

Almost every public method in this codebase has an XML doc that includes a "why" paragraph alongside the "what." Same for non-obvious inline comments. The bar: a reader who's never seen the file before should be able to tell whether a change to the line breaks something they care about, without reading other files.

This is also why XML doc generation is enabled on the production projects (`<GenerateDocumentationFile>true</GenerateDocumentationFile>`) and why most warning codes are kept on. The XML docs ship in the NuGet packages so consumer-side IDE tooltips show the rationale.

## Arrange / act / assert in tests

Every test follows the pattern:

```csharp
[Fact]
public async Task DoesTheThing_WhenContext_AssertOutcome()
{
    // arrange — what setup matters, and why this particular shape
    var (svc, db, _) = BuildService();
    await SeedUserAsync(db, "alice", "alice@example.com");

    // act — the single behavior under test
    var result = await svc.ListUsersAsync(new AdminListFilter { Search = "ali" }, CancellationToken.None);

    // assert — what we're proving, and why this matters
    result.TotalCount.Should().Be(1);
    result.Results.Should().ContainSingle(r => r.UserName == "alice");
}
```

Why the comments matter: when a test fails later, a maintainer should be able to read it and tell whether the failure indicates a regression or a deliberate behaviour change. "Should it still work this way?" is the question; the comments are the answer.

Naming: `MethodUnderTest_WhenContext_ExpectedOutcome`. Examples:
- `ListUsersAsync_AppliesSearchAndPagination_ReturnsExpectedSlice`
- `RotateRefreshTokenAsync_PresentedConsumedToken_TriggersReuseCascade`

## Constants over magic strings

If a string crosses a boundary — wire format, claim type, role name, policy name — it lives in `AuthenticationService.Shared.Constants`. Both sides reference the constant. Renaming the value in one place breaks compilation in both, which is the point.

Examples:

| Constants class | Members | Use case |
|---|---|---|
| `ClaimConstants` | `Sub`, `Sid`, `Jti`, `Name`, `Email`, `Role`, `Exp`, `ClientId`, `Scope`, `Azp` | JWT claim type names |
| `PolicyConstants` | `AdminOnly` | Authorization policy names |
| `RolesConstants` | `Admin`, `DefaultUser` (+ `.Normalised.*`) | Identity role names |
| `AuthSchemeConstants` | `Bearer`, `BearerPrefix` | `Authorization` header values |
| `SecurityEventIds` (auth service only) | 1001 LoginSucceeded, ... 5xxx admin events | SIEM event IDs |

## Settings classes own their validation

Every settings class exposed via `IOptions<T>` carries `[Required]`, `[Range]`, etc. data annotations, registered with `AddOptions<T>().Bind(...).ValidateDataAnnotations().ValidateOnStart()`. A misconfigured deployment fails at startup with a named-field error, not at the first request that hits the misconfigured code path.

The corresponding test fixture (e.g. `ServiceTokenClientOptionsTests`) drives `Validator.TryValidateObject` directly, asserting each `[Required]` field individually trips validation when nulled.

## DTOs use DataAnnotations

Inbound DTOs (`AuthenticationService.Shared.Dtos.*`) carry `[Required]`, `[MaxLength]`, `[EmailAddress]`, etc. ASP.NET Core ModelState validation catches malformed payloads before the controller runs. Each annotation is justified in an XML doc comment ("MaxLength matches the column width", "EmailAddress catches obvious typos before we hit Identity").

## File organisation

```
AuthenticationService/
├── Controllers/                    ← HTTP surface
├── Services/                       ← business logic (interfaces in Services/, impls alongside)
├── Services/Hosted/                ← BackgroundService implementations
├── Middleware/                     ← request pipeline pieces
├── Storage/                        ← DbContext, seeders, EF configuration
├── Settings/                       ← IOptions<T> classes
├── Constants/                      ← auth-service-only constants (e.g. SecurityEventIds)
├── Observability/                  ← OTel instrumentation (AuthMetrics, etc.)
├── Logging/                        ← Serilog enrichers, sinks
├── Helpers/                        ← cross-cutting utility methods
├── Extensions/                     ← extension methods on framework types
├── Entities/                       ← EF entity classes
└── Pages/                          ← Razor pages (ResetPassword, AcceptInvitation)
```

Tests mirror the source tree:

```
Tests/AuthenticationService.Tests/
├── Controllers/
├── Services/
├── Middleware/
└── ...                             (same layout as the source project)
```

A new file `Foo.cs` under `AuthenticationService/Services/` gets a `FooTests.cs` under `Tests/AuthenticationService.Tests/Services/`. No exceptions.

## Public surface gets XML docs

Every public type and method on the API + libraries carries an XML doc summary. The narrative quality is non-negotiable — drop the `///` if there's nothing meaningful to say. (`<NoWarn>$(NoWarn);1591</NoWarn>` suppresses the missing-doc warning for internal-only members.)

Examples:

```csharp
/// <summary>
/// Resolves OAuth client-credentials tokens for outgoing service-to-service calls.
/// Per-process singleton; caches tokens by <c>(audience, scopes)</c> tuple; refreshes
/// proactively at ~80% of the token's lifetime; deduplicates concurrent refresh
/// attempts so a thundering herd at expiry hits <c>/oauth/token</c> exactly once.
///
/// <para>The typical caller is <c>ServiceTokenHandler</c>, registered automatically
/// against an <c>HttpClient</c> via <c>AddServiceToken("aud", scopes)</c>. Direct
/// injection is also fine for non-HttpClient scenarios (gRPC, SignalR, etc.).</para>
/// </summary>
public interface IServiceTokenProvider { ... }
```

Consumers see this in their IDE tooltip. The cost of writing it once is paid back every time someone hovers.

## SemaphoreSlim / ConcurrentDictionary > lock

When a class has shared mutable state across requests (cache, refresh lock, etc.), prefer:
- `ConcurrentDictionary<TKey, TValue>` for the data.
- `SemaphoreSlim` for async-safe coordination.

Avoid raw `lock(_x)` for cross-async-await coordination — it doesn't release across an `await` boundary.

The provider in `TokenClientLib` is the canonical example.

## Test doubles

NSubstitute for mocking interfaces. Real instances when the collaborator's behaviour is itself part of what's being tested (e.g. `EcdsaKeyProvider` in `JWTServiceTests` uses a real instance because the test asserts on the JWKS document it produces).

For HTTP: use a custom `HttpMessageHandler` subclass over `IHttpClientFactory` mocking. See `Tests/AuthenticationService.TokenClientLib.Tests/Helpers/StubHttpMessageHandler.cs` for the pattern.

## Commit hygiene

- One logical change per commit. "Add scope policy + tighten password rules" is two commits, not one.
- First line of the message: imperative mood, no trailing period (`Add AddScopePolicy helper`), under 70 chars.
- Body explains the *why*. Same convention as code comments.
- Co-authored-by trailer for AI-assisted commits per the existing convention in this repo.

## See also

- [development/testing.md](testing.md) — running and writing tests
- [development/adding-an-endpoint.md](adding-an-endpoint.md) — practical recipe applying all of the above
