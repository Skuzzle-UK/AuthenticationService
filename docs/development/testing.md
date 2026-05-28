# Testing

Five test projects, **619 unit tests** total + **15 integration tests**. Two layers — fast unit feedback for everyday work, slower integration tests for the cross-cutting / DB-shape stuff.

## Layout

| Project | Type | Tests | Duration | When |
|---|---|---|---|---|
| `Tests/AuthenticationService.TokenValidationLib.Tests` | Unit | 10 | ~0.2s | Every commit |
| `Tests/AuthenticationService.TokenClientLib.Tests` | Unit | 38 | ~1s | Every commit |
| `Tests/AuthenticationService.Shared.Tests` | Unit | 78 | ~0.1s | Every commit |
| `Tests/AuthenticationService.Tests` | Unit | 493 | ~3s | Every commit |
| `AuthenticationService.IntegrationTests` | Integration | 15 | ~60s | Every PR |

**Zero skipped tests.** Workarounds for provider quirks (SQLite ↔ DateTimeOffset, etc.) live in a test-project subclass of `DatabaseContext` so production code stays provider-agnostic.

Stack: **xUnit** runner, **AwesomeAssertions** for fluent assertions, **NSubstitute** for mocking, **EF Core SQLite InMemory** for unit tests that need EF, **.NET Aspire** for integration tests.

## Running

```bash
# Fast feedback — unit tests across all projects (~3s)
dotnet test Tests/

# Integration tests (~60s — boots real MySQL + Redis + smtp4dev containers)
dotnet test AuthenticationService.IntegrationTests/

# Everything
dotnet test
```

Integration tests need Docker (or a Docker-compatible runtime — Rancher Desktop, Podman Desktop). The first run pulls the MySQL / Redis / smtp4dev images (~30s); subsequent runs reuse them and finish in under a minute.

### Running against a non-MySQL database

The Aspire AppHost picks the DB container based on a single switch — set it either as a CLI arg (`--db-provider=<name>` for `dotnet run --project AuthenticationService.AppHost`) or as the `INTEGRATION_DB_PROVIDER` environment variable (which `dotnet test` propagates to the AppHost). Supported values: `MySQL` (default), `SqlServer`, `PostgreSQL`.

```bash
# MySQL (default — no switch needed)
dotnet test AuthenticationService.IntegrationTests/

# SQL Server
INTEGRATION_DB_PROVIDER=SqlServer dotnet test AuthenticationService.IntegrationTests/

# PostgreSQL
INTEGRATION_DB_PROVIDER=PostgreSQL dotnet test AuthenticationService.IntegrationTests/
```

PowerShell:

```powershell
$env:INTEGRATION_DB_PROVIDER = "SqlServer"; dotnet test AuthenticationService.IntegrationTests/
```

The same scenario suite runs against every provider — there's no provider-specific test branching. First run pulls the `mcr.microsoft.com/mssql/server` (~700 MB) or `postgres` image, so budget extra time.

**CI runs all three in parallel** via the [matrix in `.github/workflows/ci.yml`](../../.github/workflows/ci.yml) — every PR gets MySQL + SqlServer + PostgreSQL coverage as three jobs. `fail-fast: false` so a flake on one doesn't taint the other results.

Inside a test, the active provider is surfaced as `AppHostFixture.DbProvider` — branch on it only when a provider-specific edge case genuinely needs verifying (the goal is full parity, not three forks of the same scenario). Test helpers like `CreateDbContextAsync` and `ConfigureDbContextProvider` on `IntegrationTestBase` switch on `DbProvider` so test code stays provider-agnostic.

### Multi-provider quirks suite (opt-in, all three in one run)

The CI matrix is the bulk safety net, but it's only triggered on PR / push-to-master. For local fast feedback when touching the EF model or the `IsMySql()`-gated runtime workarounds, there's a small focused suite that boots all three providers in **one** `dotnet test` invocation:

```bash
dotnet test AuthenticationService.IntegrationTests/ --filter "Category=MultiProviderQuirks"
```

The suite (in `AuthenticationService.IntegrationTests/Quirks/`) currently exercises:

- **DateTimeOffset round-trip on `User.CreatedAt`** — verifies the offset comes back zero on every provider (MySQL drops it; Postgres normalises to UTC; SqlServer preserves but the service uses `UtcNow` so offset=zero is what we expect).
- **DateOnly round-trip on `User.DateOfBirth`** — MySQL goes through the `DateOnly?→DateTime?` value converter in `DatabaseContext.OnModelCreating`; SqlServer + Postgres map natively. All three should hand back the same `DateOnly`.
- **Migrations applied cleanly** — asserts `GetAppliedMigrationsAsync()` is non-empty (auth's `Database.Migrate()` actually ran) and `GetPendingMigrationsAsync()` is empty (every migration in the provider's assembly was applied). We intentionally skip `HasPendingModelChanges()` — its model-differ flags annotation-level differences that don't translate to schema changes (false positives are easy to hit with EF tools/runtime version skew). Real model drift surfaces either as a non-empty migration when someone runs `dotnet ef migrations add` or as a query failure in the CI matrix — both higher-signal than the differ.

It's opt-in (tagged `[Trait("Category", "MultiProviderQuirks")]`) because booting three container sets serially adds ~90s of walltime even with cached images. Default `dotnet test` and the CI matrix both skip the suite (`--filter "Category!=MultiProviderQuirks"` in CI; not selected by default locally) so they aren't redundant with the matrix coverage.

All three quirks tests run cleanly locally on Docker Desktop for Windows + WSL2 / Linux Docker. SQL Server's container is the slowest to boot (~30s reaching healthy on a warm image) so the fixture's `ReadinessDeadline` defaults to 5 minutes — comfortable headroom for cold pulls.

**One important piece of plumbing makes this work:** the SqlServer + PostgreSQL migrations live in separate assemblies (`AuthenticationService.Migrations.SqlServer` / `…Postgres`) that aren't `ProjectReference`d from the main project — they'd form a build cycle since *they* reference the main project for `DatabaseContext`. The post-build copy targets land the DLLs in the main project's `bin/` folder, but .NET Core's default assembly loader uses `deps.json` for `Assembly.Load(AssemblyName)` resolution — a DLL dropped into the bin folder without being in `deps.json` is invisible. So `Program.cs` registers an `AssemblyLoadContext.Default.Resolving` hook that maps any `AuthenticationService.Migrations.*` lookup to `LoadFromAssemblyPath` against the bin folder. Without this hook EF Core's `MigrationsAssembly("AuthenticationService.Migrations.SqlServer")` setting throws `FileNotFoundException` at the first `Database.Migrate()` call. See [`Program.cs`](../../AuthenticationService/Program.cs) for the implementation.

Extending the suite is straightforward — add tests to `MultiProviderQuirksTestsBase`; they run once per provider via the three concrete subclasses (`MySqlMultiProviderQuirksTests`, `SqlServerMultiProviderQuirksTests`, `PostgresMultiProviderQuirksTests`).

## What's covered

**Unit tests** cover every public method on every public class — controllers, services, validators, middleware, helpers, hosted services. The detailed coverage map is in [`Tests/README.md`](../../Tests/README.md).

**Integration tests** cover end-to-end scenarios that exercise real infrastructure (real MySQL, real Redis, real SMTP via smtp4dev):

| # | Scenario | Asserts |
|---|---|---|
| 1 | Register → confirm email → login | Full onboarding pipeline; QueuedEmailService delivery; data-protection-protected confirmation token |
| 2 | Refresh token rotation | Old refresh row consumed in MySQL, new row in same family |
| 3 | Refresh token reuse cascade | Reuse triggers full nuke: all families revoked, security stamp rotated, suspicious-activity email sent |
| 4 | Password change → "wasn't me" lock | Lock token round-trips through email; account locked indefinitely |
| 5 | Rate limiter integration | Burst against `/authenticate` trips the global 4/10s cap (real Redis Lua scripts) |
| 6 | Threshold escalation worker | `RunSweepAsync` against real MySQL stamps `LockedAt` + fires lock cascade |
| 7 | JWKS / OIDC discovery | A consumer using only the published JWKS can validate a JWT issued by the auth service — the actual production contract |
| 8 | Admin invitation flow | Admin POSTs `/api/Admin/users`, invitee receives email + sets initial password, lock/unlock round-trip persists in MySQL |
| 9 | Admin force-password-reset | Admin triggers reset, email lands with link, user resets, old refresh tokens revoked |
| 10 | OAuth client-credentials happy path | Admin creates client → `/oauth/token` issues service JWT with the expected claim shape + LastUsedAt stamped |
| 11 | OAuth scope authorisation | Requesting an unauthorised scope returns `invalid_scope`; the same client's authorised scope still works; partial scope requests fail all-or-nothing |
| 12 | **Service-token client end-to-end** | A typed client wired with `AddServiceToken("aud", "scope")` fetches a real token via the live auth service, two calls share one token (cache hit), and an `invalid_token` 401 from the downstream triggers invalidate-and-retry-once with a freshly-minted token (different jti). |

## Conventions

All tests follow the **arrange / act / assert** pattern with comments explaining *why* — not just *what* — the assertion matters. When a test fails later, a maintainer should be able to read the comments and tell whether the failure indicates a regression or a deliberate behaviour change.

See [development/conventions.md](conventions.md) for the rest of the code style.

## Why SQLite InMemory for unit tests

The unit suite uses **EF Core SQLite InMemory** rather than the EF Core InMemory provider because:
- SQLite honours `ExecuteUpdateAsync` / `ExecuteDeleteAsync` / transactions — the EF Core InMemory provider rejects all three.
- SQLite InMemory is genuinely in-memory (no disk, no network) so tests stay sub-second.

Where SQLite's quirks bite (e.g. `DateTimeOffset` binary comparisons), the workaround lives in `Tests/AuthenticationService.Tests/Helpers/TestDatabaseContext.cs` — a subclass of `DatabaseContext` that production code doesn't know about. Production stays provider-agnostic; tests opt in.

## Why .NET Aspire for integration tests

`Aspire.Hosting.Testing` boots the AppHost graph (MySQL + Redis + smtp4dev) in-process. The same graph that the dev F5 flow uses — real services, real DB schema, real SMTP. Three production-affecting bugs the unit tests couldn't have caught were caught here:

1. **`DateOnly` round-trip** — Oracle's MySQL provider can't deserialise DATE columns back into `DateOnly`. Fixed via `ValueConverter` in `DatabaseContext.OnModelCreating`.
2. **`DateTimeOffset.MaxValue` overflow** — Oracle's provider tries to write the fractional-second precision past MySQL's DATETIME max. Fixed via `LockoutDurations.Indefinite` (`9999-12-31T00:00:00Z`).
3. **`Contains-on-collection` SQL translation** — `Where(t => list.Contains(...))` errors out on Oracle's provider. Fixed via per-jti loop in `RevokedTokenReplayEscalationService`.

All three would be obviated by migrating to `Pomelo.EntityFrameworkCore.MySql` — see [`TODO.md`](../../TODO.md) Tier 4 ("blocked: waiting on Pomelo 10 release").

## CI

GitHub Actions workflow at [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml). Two jobs:

- **Unit tests** on every push. Fast feedback (~3s).
- **Integration tests** on PR + push-to-main. Slower (~60s), runs against real MySQL / Redis / smtp4dev via Aspire. Runner is `ubuntu-latest` (Docker pre-installed).

Concurrency group cancels superseded runs to avoid queueing duplicate work on noisy push cycles.

## See also

- [`Tests/README.md`](../../Tests/README.md) — detailed per-file coverage map
- [`AuthenticationService.IntegrationTests/README.md`](../../AuthenticationService.IntegrationTests/README.md) if present — integration-test-specific patterns
- [development/conventions.md](conventions.md) — comment style, naming, file layout
- [development/adding-an-endpoint.md](adding-an-endpoint.md) — practical walk-through of adding a new feature
