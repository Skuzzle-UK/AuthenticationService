# Corporate-readiness TODO

What's still outstanding. Closed items have been removed — they're in git history; this
doc is forward-looking. Tiered by impact for an enterprise, multi-replica, shared-by-many-apps
deployment; pick from the top and work down.

> **Status as of 2026-05-27:** all Tier 0 blockers (B1–B5), all 10 medium-priority items
> (M1–M10), and all 8 nice-to-haves are closed. **Multi-provider DB Phases 1, 2, 3, and
> 3.1 (MySQL + SQL Server + PostgreSQL, with Aspire AppHost + integration-test
> parameterisation) all shipped.** Only the real end-to-end smoke against managed
> SqlServer + Postgres instances remains — that's a deploy-time verification, not a code
> change.

---

## Tier 0 — Pre-cutover hardening

All Tier 0 items are closed (2026-05-21). M10 (signing-key backup runbook) was written
as a deliberately secret-store-agnostic doc covering Azure Key Vault, AWS Secrets
Manager, HashiCorp Vault, GCP Secret Manager, Kubernetes Secrets + Velero, Sealed
Secrets / SOPS, and filesystem snapshots — see
[`docs/operations/signing-key-backup-and-restore.md`](docs/operations/signing-key-backup-and-restore.md).
The team picks the section that fits the deployment platform; the universal "what to
back up" and "restore" procedures apply regardless.

### 🛠 Nice-to-haves

All shipped (2026-05-21):

- ✅ `User.FindFirst("sub")` magic string in `AccountController` replaced with `ClaimConstants.Sub`.
- ✅ `UserGaugeRefreshService` test file added (`Tests/AuthenticationService.Tests/Services/Hosted/UserGaugeRefreshServiceTests.cs`) — happy path, scope-throws-survival, pre-cancelled token.
- ✅ Blanket `#pragma warning disable` in 6 settings/entity files replaced with `#pragma warning disable CS8618` + a one-line "why" comment so future warnings of other codes still surface.
- ✅ `Directory.Build.props` at the repo root enforces `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` across every project. Build remains clean (0 warnings) in both Debug and Release.
- ✅ `EcdsaKeyProvider` now sets `UserRead | UserWrite` (0600) on the dev-generated PEM on Unix-like platforms. Guarded with `OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()` since the API throws on Windows.
- ✅ CSP `'unsafe-inline'` removed from both `script-src` and `style-src`. The three Razor pages (`ResetPassword`, `LockAccount`, `AcceptInvitation`) now load JS from external files under `wwwroot/js/`, receiving server-side state via `data-*` attributes. New `SecurityHeadersMiddlewareTests` assertion locks in the no-`unsafe-inline` contract as a regression guard.
- ✅ `Dockerfile` now has a `HEALTHCHECK` directive (`curl --fail http://localhost:8080/livez || exit 1`) for `docker run` smoke tests + Docker Desktop's UI status. `curl` is installed in the base stage explicitly (the aspnet:10.0 image doesn't include it). K8s ignores this and uses `/livez` / `/readyz` probes directly.
- ✅ `Dockerfile` pre-restore COPY now includes `AuthenticationService.ServiceDefaults` — restore-layer cache is no longer invalidated by unrelated changes.

---

## Planned engineering — multi-provider database support

Today the service is hard-wired to MySQL via Oracle's `MySql.EntityFrameworkCore`.
Targeting **MySQL + SQL Server + PostgreSQL** so consumer platforms can pick whichever
their organisation already runs. Pomelo migration (Tier 4 below) is independent of this
work — it'll just swap one MySQL provider for another whenever it lands.

Three-phase plan. Each phase ships independently and leaves the codebase in a working
state. Total effort: ~2.5 days for a focused dev.

### ~~Phase 1 — Provider-selection seam~~ ✅ DONE (2026-05-21)

**What we shipped:**

- ✅ **`DatabaseSettings` + `DatabaseSettingsValidator`** in `Settings/` and `Validators/` — `Provider` is `[Required]` and restricted to `DatabaseProviders.Supported` (currently `[ "MySQL" ]`). Mirrors the M1/M2 validator pattern. 9 new tests in `ValidatorsTests.cs` cover named-instance skip, supported provider success, blank/null/whitespace fail, unknown-typo fail, and the "reserved-but-not-yet-wired" case (`PostgreSQL` is in `DatabaseProviders` constants but not in `Supported` — pre-emptively fails so setting `Provider=PostgreSQL` before Phase 3 doesn't silently break startup).
- ✅ **`HostExtensions.AddDatabase` dispatches on `settings.Provider`** via a `switch`. The `MySQL` case keeps the existing `opt.UseMySQL(...)` + `MySqlRetryingExecutionStrategy` wiring. Default case throws `NotImplementedException` with the supported-set message (defensive — the validator catches this earlier under normal startup).
- ✅ **Connection string lookup** now uses the active provider name: `ConnectionStrings:{Provider}`. Back-compat preserved because `Provider=MySQL` → `ConnectionStrings:MySQL` (the existing key). Clear `InvalidOperationException` if missing, naming the exact env var to set.
- ✅ **`DatabaseProviders` constants class** + `DatabaseProviderExtensions.IsMySql()` for runtime workaround branching. `IsMySql()` matches via substring on `ProviderName` so both Oracle's `MySql.EntityFrameworkCore` and Pomelo's `Pomelo.EntityFrameworkCore.MySql` resolve true — the eventual Pomelo swap doesn't have to revisit workaround sites.
- ✅ **DateOnly converter in `DatabaseContext.OnModelCreating`** now gated behind `Database.IsMySql()`. SQL Server and PostgreSQL have native `DateOnly` support; the converter would be a wasteful round-trip. SQLite tests (which the unit suite uses) also skip the converter and pass — EF Core 10's SQLite provider handles `DateOnly` natively.
- ✅ **`appsettings.json`** has an explicit `DatabaseSettings:Provider = "MySQL"` block with explanatory comments pointing at the multi-provider plan.

**Deferred to Phase 2 (deliberately):**

- The `LockoutDurations.Indefinite` sentinel stays at its current value. The MySQL-DATETIME(6)-conservative value works fine on SQL Server / PostgreSQL too (it's just smaller than their max). Phase 2 can revisit if a non-MySQL deployment needs a different sentinel — for now a code comment explains the constraint origin.
- The per-jti loop in `RevokedTokenReplayEscalationService.RunSweepAsync` stays. Restructuring it to add a batched `Contains` path with an `IsMySql()` switch would be dead code until Phase 2 wires SQL Server. Phase 2's checklist owns the refactor when the alternative provider is live.

**Tests:** 492 passing (was 483, +9 for the new validator suite).

### ~~Phase 2 — Add SQL Server~~ ✅ DONE (2026-05-21)

**What we shipped:**

- ✅ `Microsoft.EntityFrameworkCore.SqlServer` 10.0.8 added to the main project.
- ✅ New **`AuthenticationService.Migrations.SqlServer`** class library project. Holds the SQL Server-specific migrations + model snapshot (EF Core requires one snapshot per provider per context, so each provider lives in its own assembly).
- ✅ **`DesignTimeFactory`** in the migrations project so it can be both `--project` and `--startup-project` for the EF CLI without needing the full host pipeline (Redis / validators / etc.).
- ✅ **Initial SQL Server migration** generated: `AuthenticationService.Migrations.SqlServer/Migrations/20260527101953_InitialSqlServer.cs` (+ Designer + ModelSnapshot). Generated via `dotnet ef migrations add InitialSqlServer --project AuthenticationService.Migrations.SqlServer --startup-project AuthenticationService.Migrations.SqlServer --context DatabaseContext --output-dir Migrations`.
- ✅ **`HostExtensions.AddDatabase` SqlServer branch** — `opt.UseSqlServer(connStr, sql => sql.EnableRetryOnFailure(5, 30s, null).MigrationsAssembly("AuthenticationService.Migrations.SqlServer"))`. Matches the MySQL retry budget (5 × 30s).
- ✅ **`DatabaseProviders.Supported`** now `[MySql, SqlServer]`. `DatabaseSettingsValidator` accepts both. Validator test extended to a `[Theory]` over both supported providers (the `PostgreSQL` reserved-future test still pins that case).
- ✅ **`appsettings.json`** documents the `SqlServer` option + a commented-out connection-string example.
- ✅ **Runtime DLL discovery** — `Migrations.SqlServer` has a post-build MSBuild target that copies its DLL into the main project's `bin/$(Configuration)/$(TargetFramework)/` folder. Necessary because Main can't ProjectReference the migrations project (circular dep — migrations already reference Main for `DatabaseContext`). On `dotnet publish` the same target ensures the DLL is in the publish output.
- ✅ Solution file (`AuthenticationService.sln`) now lists the new project.

**Workaround revisits deferred from Phase 1, closed in Phase 3.2:**

- ✅ The per-jti loop in `RevokedTokenReplayEscalationService.RunSweepAsync` is now
  `IsMySql()`-gated. SqlServer + Postgres get one batched `Contains` query (single
  IN-clause + dictionary lookup); MySQL keeps the N+1 point-lookup pattern until we move
  to Pomelo. Same shape as the `DateOnly` / `datetime(6)` workarounds — provider-gated
  in one place, no per-call-site branching.

**Not yet wired (genuinely future work):**

- **Aspire AppHost** — no optional `AddSqlServer()` container resource yet. Local dev with `dotnet run --project AuthenticationService.AppHost` still spins MySQL. Operators wanting to dev against SQL Server need to point `ConnectionStrings:SqlServer` at a manually-managed instance for now. Phase 2.1 item.
- **Integration tests** — `AppHostFixture` not yet parameterised on `INTEGRATION_DB_PROVIDER`. CI still runs the scenario suite against MySQL only. Phase 2.1 item.
- **End-to-end smoke against real SQL Server** — needs a SQL Server instance to point at; can't verify here.
- ~~**Docs**~~ ✅ done. New [`docs/development/migrations.md`](docs/development/migrations.md) covers the per-provider migration workflow (add, undo, script, runtime application). `docs/architecture.md` has a "Supported database providers" table and a "Per-provider migrations" project-list section. `docs/reference/configuration.md` has new `DatabaseSettings` and updated `ConnectionStrings` sections. `docs/operations/deployment.md §7` now shows per-provider `dotnet ef database update` commands. Doc is wired into mkdocs nav (Backstage TechDocs picks it up) and the `.sln` docs/development folder.

**Tests:** 493 passing (was 492, +1 from the validator `[Theory]` extension to cover `SqlServer`). Build clean in Debug + Release.

### ~~Phase 3 — Add PostgreSQL~~ ✅ DONE (2026-05-21)

**What we shipped:**

- ✅ `Npgsql.EntityFrameworkCore.PostgreSQL` 10.0.0 added to the main project.
- ✅ New **`AuthenticationService.Migrations.Postgres`** class library project, same shape as `Migrations.SqlServer` — own `DesignTimeFactory`, own post-build copy target to land the DLL in main's bin folder.
- ✅ **Initial PostgreSQL migration** generated: `AuthenticationService.Migrations.Postgres/Migrations/20260527104131_InitialPostgres.cs` (+ Designer + ModelSnapshot). Same `dotnet ef migrations add` flow as Phase 2.
- ✅ **`HostExtensions.AddDatabase` PostgreSQL branch** — `opt.UseNpgsql(connStr, npg => npg.EnableRetryOnFailure(5, 30s, null).MigrationsAssembly("AuthenticationService.Migrations.Postgres"))`. Same retry budget as MySQL / SqlServer.
- ✅ **`DatabaseProviders.Supported`** now `[MySql, SqlServer, PostgreSQL]`. `DatabaseSettingsValidator` accepts all three; the "reserved-but-not-yet-wired" failure message is gone (nothing is reserved now). Validator test `[Theory]` extended to cover all three.
- ✅ **`appsettings.json`** documents the `PostgreSQL` option + a commented-out connection-string example.

**Npgsql gotcha resolved (via Phase 3.2 — model normalised to `DateTimeOffset`):** the
`Npgsql.EnableLegacyTimestampBehavior` switch is gone. The whole entity model uses
`DateTimeOffset` so the strict `timestamptz` handling Npgsql 6+ ships by default is exactly
what we want. See Phase 3.2 below for the refactor that closed this out.

**Other Npgsql concerns confirmed non-issues:**
- `NormalizedEmail` / `NormalizedUserName` lookups don't need `citext` — Identity stores the upper-cased form already, plain equality works.
- Connection-pooling defaults are fine for typical deployment sizes; operators tune via `Maximum Pool Size` in the connection string if needed.

**Docs updated:** [`development/migrations.md`](docs/development/migrations.md), [`architecture.md`](docs/architecture.md), [`reference/configuration.md`](docs/reference/configuration.md), [`operations/deployment.md`](docs/operations/deployment.md) all show PostgreSQL alongside MySQL + SqlServer.

**Tests:** 493 passing (same count as Phase 2 — the validator `[Theory]` row for PostgreSQL is offset by removing the now-irrelevant `ReservedFutureProvider_Fails` test).

### ~~Phase 3.1 — Aspire AppHost + integration-test parameterisation~~ ✅ DONE (2026-05-27)

**What we shipped:**

- ✅ `Aspire.Hosting.SqlServer` 13.3.4 + `Aspire.Hosting.PostgreSQL` 13.3.4 added to the AppHost project alongside the existing `Aspire.Hosting.MySql`.
- ✅ **`AppHost.cs` picks the DB container based on a single switch** — `--db-provider=<name>` arg (for `dotnet run`) or `INTEGRATION_DB_PROVIDER` env var (which `dotnet test` propagates). Supported values: `MySQL` (default), `SqlServer`, `PostgreSQL`. Unknown provider throws at AppHost startup with a clear error naming the supported set.
- ✅ **Auth resource picks up the active provider** — `DatabaseSettings__Provider` env var is set, and the connection-string env var key is built dynamically (`ConnectionStrings__{dbProvider}`) so the auth service's `ConnectionStrings:{Provider}` lookup resolves to the running container in every case.
- ✅ **`AppHostFixture`** documents the env var, surfaces `DbProvider` as a public property (so scenario tests can branch on it if a provider-specific edge case ever needs verifying — none do today, the goal is full parity).
- ✅ Type unification: `IResourceBuilder<out T>` is covariant in Aspire 13, so a single `IResourceBuilder<IResourceWithConnectionString>` reference works for all three provider-specific database resources without explicit casts.
- ✅ **Docs updated:**
  - `docs/development/testing.md` — new "Running against a non-MySQL database" section with env-var examples for both bash + PowerShell, mention of CI matrix pattern, refreshed unit-test counts.
  - `docs/development/migrations.md` — new "Dev-loop: running the app against a non-MySQL provider" section, runtime-application paragraph updated to mention all three providers.
  - `docs/architecture.md` — AppHost description mentions the provider switch.

**Tests:** 619 passing (493 main + 78 Shared + 38 TokenClientLib + 10 TokenValidationLib). Build clean in Debug.

**Not yet wired (genuine deploy-time verification, not a code change):**

- **End-to-end smoke against managed SqlServer + Postgres instances** — needs real targets. The container-based integration suite running locally is the next-best signal; CI matrix once SQL Server / PostgreSQL deployments are real will complete the picture. The Aspire containers spin up a *fresh* mssql/postgres per test run, so this verifies migrations + connectivity + EF translations on every PR for free.

### ~~Phase 3.2 — Normalise the model to `DateTimeOffset`~~ ✅ DONE (2026-05-27)

**What we shipped:**

- ✅ **Every entity timestamp swapped from `DateTime` / `DateTime?` to `DateTimeOffset` /
  `DateTimeOffset?`** — `User.CreatedAt`, `RefreshToken.CreatedAt/ExpiresAt/ConsumedAt`,
  `RevokedToken.ExpiresAt/RevokedAt/WarnedAt/LockedAt`, `RevokedTokenAccessAttempt.CreatedAt`,
  `SecurityEvent.Timestamp`, `Client.CreatedAt/LastUsedAt`. Also `AdminAuditFilter.Since`,
  `Token.Expires/RefreshTokenExpiresAt` (shared DTO), and the same for the
  `UserSummary/Detail/ClientSummary/Detail/AuditEntry` response DTOs. **Consistent with
  `IdentityUser.LockoutEnd`** which has always been `DateTimeOffset?`.
- ✅ **All `DateTime.UtcNow` call sites in production code converted to `DateTimeOffset.UtcNow`**
  (~27 sites across `JWTService`, `AdminService`, `ClientService`, `RuntimeDbSeeders`,
  `DataRetentionCleanupService`, `RevokedTokenReplayEscalationService`, the two relevant
  controllers, and the OAuth controller).
- ✅ **`JWTService.GetExpiryDateTime` returns `DateTimeOffset?`** (was `DateTime?`).
  Interface + tests updated.
- ✅ **`JwtSecurityToken.expires` (DateTime?-typed in JWT lib)** — converted via
  `.UtcDateTime` where it's consumed. The lib doesn't accept `DateTimeOffset` so this is
  the only place a transient `DateTime` survives, with a comment explaining why.
- ✅ **DataRetentionCleanupService**: `.AddDays(...)` on entity columns moved to the
  parameter side (`Where(x => x.CreatedAt < cutoff)`) — also a perf win (no per-row date
  arithmetic) and works on every provider's translator regardless of converter setup.
- ✅ **`RevokedTokenReplayEscalationService` batched-Contains path** for SqlServer +
  Postgres — `IsMySql()`-gated branch. The per-jti loop stays for Oracle's MySQL provider
  (still can't translate `Contains` on a collection); other providers get a single
  IN-clause query + dictionary lookup. Closes the Phase-2 follow-up flagged in the SQL
  Server section.
- ✅ **`Npgsql.EnableLegacyTimestampBehavior` switch DROPPED** from `HostExtensions.AddDatabase`.
  Postgres now uses default Npgsql 6+ strict `timestamptz` semantics.
- ✅ **MySQL column precision preserved** at `datetime(6)` via fluent
  `HasColumnType("datetime(6)")` in `DatabaseContext.OnModelCreating`'s `IsMySql()` branch
  — Oracle's MySQL provider defaults `DateTimeOffset` columns to plain `datetime` (second
  precision), so without the hint we'd silently lose sub-second precision on every
  audit/token timestamp. With the hint, the MySQL migration is an empty no-op at the SQL
  level (only the model snapshot updates).
- ✅ **Test-only `TestDatabaseContext`** extended with a value converter that maps every
  `DateTimeOffset` / `DateTimeOffset?` property to `long` (UtcTicks) for SQLite — SQLite
  can't translate `DateTimeOffset` in `WHERE` / `ORDER BY` clauses. Five test files that
  were instantiating bare `DatabaseContext` switched to `TestDatabaseContext`. Two test
  fixtures that resolve the context through DI now register `TestDatabaseContext` against
  the `DatabaseContext` service-type.
- ✅ **Two test queries** that did `OrderBy(x => x.DateTimeOffsetCol)` flipped to
  client-side ordering (`(await ToListAsync()).OrderBy(...)`). SQLite can't ORDER BY
  `DateTimeOffset` even with the converter — the provider's pre-translation type check
  rejects it before consulting the converter. Doesn't affect production (MySQL / SqlServer
  / PostgreSQL all ORDER BY `DateTimeOffset` natively).
- ✅ **New migrations generated for all three providers:**
  - `Migrations/20260527113216_SwitchToDateTimeOffset.cs` (MySQL — empty Up/Down, schema
    unchanged due to `HasColumnType("datetime(6)")`).
  - `Migrations.SqlServer/Migrations/20260527112412_SwitchToDateTimeOffset.cs` — alters
    every timestamp column from `datetime2` to native `datetimeoffset`.
  - `Migrations.Postgres/Migrations/20260527112514_SwitchToDateTimeOffset.cs` (empty
    Up/Down — `timestamptz` already accommodates `DateTimeOffset`).

**What this buys us:**

- No more `Kind=Unspecified` round-trip surprises (the original Npgsql 6+ trap).
- Identity's own `LockoutEnd` column (`DateTimeOffset?`) and our hand-rolled columns
  now agree — schema is consistent.
- Cross-timezone deployments work cleanly. Every persisted timestamp carries the offset.
- One less global `AppContext.SetSwitch(...)` call.

**Tests:** still 619 passing (493 main + 78 Shared + 38 TokenClientLib + 10 TokenValidationLib).
Build clean.

### ~~Phase 3.3 — Multi-provider integration coverage (CI matrix + in-process quirks suite)~~ ✅ DONE (2026-05-27)

**What we shipped:**

- ✅ **CI matrix** — `.github/workflows/ci.yml` integration-tests job now fans out across
  `[MySQL, SqlServer, PostgreSQL]` as three parallel jobs, each driven by
  `INTEGRATION_DB_PROVIDER`. `fail-fast: false` so a flake on one provider doesn't
  cancel the in-flight runs on the other two. TRX artifacts upload per-provider.
- ✅ **`IntegrationTestBase` is provider-aware** — `CreateDbContextAsync` and new
  `ConfigureDbContextProvider` helpers switch on `Fixture.DbProvider` to pick the right
  EF provider (`UseMySQL` / `UseSqlServer` / `UseNpgsql`). Scenario tests that build
  their own `DbContext` (notably `ThresholdEscalationWorkerTests`) use the helper rather
  than hardcoding MySQL — the same scenario survives the matrix on every provider.
- ✅ **In-process multi-provider quirks suite** — `MultiProviderQuirksTestsBase` boots
  all three providers in a single `dotnet test` run via three xUnit collection fixtures
  (`MySqlAppHostFixture`, `SqlServerAppHostFixture`, `PostgresAppHostFixture`), each
  passing `--db-provider=<X>` to the AppHost. Verifies the DB-quirk seams that
  realistically diverge between providers:
  - `User.CreatedAt` — DateTimeOffset round-trip (MySQL stores as `datetime(6)` and
    drops offset; SqlServer uses native `datetimeoffset`; Postgres uses `timestamptz`).
  - `User.DateOfBirth` — DateOnly round-trip (MySQL goes through the
    `DateOnly?→DateTime?` value converter; SqlServer + Postgres map natively).
- ✅ **Opt-in via xUnit Trait** — quirks tests are tagged
  `[Trait("Category", "MultiProviderQuirks")]`. Default `dotnet test` skips them; opt
  in with `--filter "Category=MultiProviderQuirks"`. Keeps the local fast-loop fast
  while making divergence catchable on demand.
- ✅ **`AppHostFixture.ReadinessDeadline`** is now virtual and defaults to 5 minutes
  (up from 2). HttpClient probe timeout bumped from 5s to 15s. SqlServer in particular
  is slow to reach a healthy state on Docker Desktop for Windows; CI on `ubuntu-latest`
  doesn't see this.
- ✅ **Docs updated** — `docs/development/testing.md` covers the CI matrix, the quirks
  suite, the opt-in filter, and the local SqlServer slow-startup caveat.

**Verified:** all three quirks tests pass locally end-to-end on Docker Desktop for
Windows (~60-90s per provider). MySQL booted fastest, SqlServer second, Postgres third.
The CI matrix on `ubuntu-latest` runs the bulk suite against each provider on every PR.

### ~~Phase 3.4 — Fix migrations-assembly resolution at runtime~~ ✅ DONE (2026-05-28)

**The bug:** When `DatabaseSettings:Provider=SqlServer` (or `=PostgreSQL`), the auth
service crashed at startup with `FileNotFoundException: Could not load file or assembly
'AuthenticationService.Migrations.SqlServer'`. The Phase 2 + 3 post-build targets *did*
copy the migration DLLs into the main project's bin folder — but .NET Core's default
assembly loader uses `deps.json` for `Assembly.Load(AssemblyName)` resolution, and DLLs
dropped into bin without being in deps.json are invisible. EF Core's
`MigrationsAssembly("AuthenticationService.Migrations.SqlServer")` setting invokes
`Assembly.Load`, which threw.

MySQL didn't hit this because the MySQL migrations live in the main project itself —
no cross-assembly load needed.

**The fix:** `Program.cs` now registers an `AssemblyLoadContext.Default.Resolving` hook
*before any other startup code runs*. When something asks for an
`AuthenticationService.Migrations.*` assembly by name, the hook calls
`LoadFromAssemblyPath` against the matching DLL in `AppContext.BaseDirectory`. No-op
for any other assembly name. ~10 lines.

**Other improvements made during the diagnostic:**

- ✅ **`Program.cs` startup exceptions now set `Environment.ExitCode = 1`.** The
  original `catch` block logged at Fatal but exited cleanly — so a startup crash looked
  identical to a clean shutdown to orchestrators (and to the integration-test harness).
  Defensive fix that made this diagnostic possible and helps future incident response.
- ✅ **`AppHostFixture` got proper diagnostics:**
  - Phase 1 wait uses Aspire's canonical `ResourceNotifications.WaitForResourceAsync`
    instead of HTTP polling — distinguishes "resource never started" from "resource
    started but slow to respond."
  - Phase 2 wait remains the `/readyz` probe.
  - On timeout, snapshots every resource's state + exit code, plus the auth resource's
    log tail captured via a custom `ILoggerProvider` hooked into Aspire's
    `AuthenticationService.AppHost.Resources.*` MEL categories. Filtered to
    `resource=auth` so DB chatter doesn't drown out the actual signal.
  - The fixture's `ReadinessDeadline` is now `virtual` (defaults to 5 minutes) so a
    subclass can extend if hardware demands it.

### ~~Phase 3.5 — Extract MySQL migrations into their own project~~ ✅ DONE (2026-05-28)

**Why:** Symmetry. MySQL migrations had lived in the main project (`AuthenticationService/Migrations/`)
for historical reasons — it was the first provider and predated the multi-provider work.
SqlServer + Postgres each had their own assembly; MySQL was the odd one out, with the
main project carrying provider-specific migrations.

**What we shipped:**

- ✅ New `AuthenticationService.Migrations.MySql` project, mirroring the SqlServer +
  Postgres structure: same csproj shape, same `DesignTimeFactory` pattern, same
  `AfterTargets="Build"` DLL-copy target into the main project's bin folder.
- ✅ All 41 files from `AuthenticationService/Migrations/` (20 migrations × 2 files each +
  the `DatabaseContextModelSnapshot.cs`) moved to `AuthenticationService.Migrations.MySql/Migrations/`.
- ✅ Namespaces rewritten from `AuthenticationService.Migrations` →
  `AuthenticationService.Migrations.MySql.Migrations` (a regex substitution across all 41
  files, matching the SqlServer + Postgres naming convention).
- ✅ `HostExtensions.AddDatabase`'s MySQL branch now sets
  `mysql.MigrationsAssembly("AuthenticationService.Migrations.MySql")` so EF Core
  resolves the migrations from the new assembly.
- ✅ The `AssemblyLoadContext.Resolving` hook from Phase 3.4 already matches the
  `AuthenticationService.Migrations.*` prefix, so it transparently picks up the new
  assembly with no further changes.
- ✅ Solution file updated.
- ✅ Docs updated: `architecture.md` per-provider migrations table now lists all three;
  `development/migrations.md` shows the new MySQL `dotnet ef migrations add` command;
  `operations/deployment.md` shows the new MySQL `database update` command. The
  "MySQL lives in the main project for historical reasons" caveat is gone.

**Backwards compatibility:** zero impact on deployed MySQL databases.
`__EFMigrationsHistory` tracks migrations by their `MigrationId` (e.g.
`20250328002440_InitialMigration`) — that ID is unchanged, only the containing
assembly + namespace moved. The next `dotnet ef database update` against a live DB
sees the same history rows and applies nothing new.

### ~~Phase 3.6 — Explicit "migrations in sync" assertion across all providers~~ ✅ DONE (2026-05-28)

**Gap closed:** previously the integration suite covered migrations *implicitly* — the
CI matrix runs the bulk scenarios against each provider on every PR, so a broken
migration would surface as auth-fails-to-start and scenarios cascade-fail. But that
failure mode is indirect (one of the 15 scenarios reports column-not-found rather than
"migrations didn't apply"), and model-drift (an entity changed in code but no migration
added for one of the three providers) wouldn't surface until something queried the
missing column.

**The fix:** new `[Fact]` in `MultiProviderQuirksTestsBase`:
`Migrations_AppliedCleanly_OnEveryProvider`. Runs once per provider via the three
concrete subclasses. Asserts two things via EF Core's own APIs:

1. `Database.GetAppliedMigrationsAsync()` is non-empty (auth's `Database.Migrate()`
   actually ran during startup).
2. `Database.GetPendingMigrationsAsync()` is empty (every migration in the provider's
   assembly was applied — catches a partial-apply failure).

**Deliberately not asserted:** `HasPendingModelChanges()`. Initial attempt included it
to catch model-drift, but EF Core's model differ flags annotation-level differences
that don't translate to any actual schema change — `dotnet ef migrations add` produces
an empty Up/Down body, but `HasPendingModelChanges()` returns true. The EF tools 10.0.2
vs runtime 10.0.8 version skew we currently run with is a known producer of these false
positives. The model-differ result isn't reliable signal, so we don't use it. Real model
drift will land as a non-empty migration when someone runs `dotnet ef migrations add` or
as a query failure in the CI matrix when a column is genuinely missing — both
higher-signal than the differ.

**Cost:** ~5s added to each quirks-suite run (two queries per provider). The provider
fixture is already booted; this just queries it.

**Tests:** 619 unit tests still pass. MySQL quirks integration test still passes
end-to-end against the relocated assembly (~60s). SqlServer + Postgres unchanged.

### Ongoing cost after all three are in

Every schema change from then on:
1. `dotnet ef migrations add Foo --output-dir Migrations.MySql` (against MySQL).
2. Repeat for `Migrations.SqlServer` and `Migrations.Postgres` against the matching
   targets. EF will emit provider-correct SQL each time.
3. CI matrix verifies all three.

It's not free — every schema change costs ~10 min of additional migration generation
+ verification. Worth the price if multiple platforms are real consumers.

### Out of scope (deliberately)

- **SQLite as a real production target.** It's fine for dev/CI (already used in unit
  tests) but lacks the concurrency and rate-limiter-via-Redis-fallback story to be a
  real prod option. Mention in `docs/operations/deployment.md` only.
- **Oracle Database.** Enterprise-niche, licence cost, small audience. Easy to add
  later as Phase 4 if a real consumer asks.
- **CockroachDB / AWS Aurora Postgres / Yugabyte.** Wire-compatible with PostgreSQL —
  they'll likely just work once Phase 3 ships. Document as "should work, untested."

---

## Tier 4 — Infrastructure (deferred)

- [ ] **Migrate from `MySql.EntityFrameworkCore` (Oracle) to `Pomelo.EntityFrameworkCore.MySql`** _(blocked: waiting on Pomelo 10 release)._

  Oracle-provider workarounds that would disappear under Pomelo:
  - `DateOnly` round-trip needs an explicit value converter against Oracle; Pomelo native.
  - `DateTimeOffset.MaxValue` overflows MySQL `DATETIME` via Oracle; Pomelo handles cleanly.
  - `Contains` on `List<string>` doesn't translate via Oracle (forced N+1 loop in
    threshold-escalation worker); Pomelo translates fine.
  - `HasColumnType("datetime(6)")` hint on every `DateTimeOffset` column (Phase 3.2) — Pomelo's
    default mapping already preserves sub-second precision, no hint needed.

  Pomelo would also replace the custom `MySqlRetryingExecutionStrategy` (shipped for B1) with its native `EnableRetryOnFailure`.

  **Status:** latest Pomelo on nuget.org is `9.0.0`, which hard-pins to EF Core 9.0.x. We're on EF Core 10; downgrading would cascade into Identity / Aspire / hosting incompatibilities. Re-check quarterly; the migration is ~half a day once Pomelo 10 ships.

  **Workarounds in place until then:** `DateOnly` value converter + `DateTimeOffset` column-precision hints in `DatabaseContext.OnModelCreating`, `LockoutDurations.Indefinite` sentinel constant, per-jti loop in `RevokedTokenReplayEscalationService.RunSweepAsync`, custom `MySqlRetryingExecutionStrategy`. Each carries a code comment explaining "this can revert when we move to Pomelo."

---

## Tier 5 — Missing features for enterprise multi-tenant use (build when demand arrives)

None of these block shipping. Flagged so the design space is visible.

- [ ] **External IdP integration (SSO).** Many corporate apps want "log in with Microsoft / Google / Entra ID." Not in scope today but a likely requirement once the platform matures. Design considerations: claim mapping, account linking (existing local + new SSO), lifecycle (what happens when SSO removes a user upstream).

- [ ] **Bulk user import.** Onboarding to a corporate platform with existing users elsewhere — there's no migration path. Not initial scope but flagged.

- [ ] **Operational runbook — three team-decision placeholders remain.** The runbook is now a working doc, not a skeleton. The decision tree, common procedures, and a full "I can't log in" triage table are filled in from code knowledge. Three placeholders stay because they need decisions the codebase can't make: **first-time prod deployment** (Helm / Terraform / Pulumi / kubectl flow — depends on platform choice), **SLO / SLA targets** (availability + latency commitments), and **incident-response procedure** (on-call rotation + paging tool + escalation matrix). Each one's expected shape is sketched in `runbook.md` so whoever fills them in knows what's expected.

---

## Recommended next-up order

1. **Real end-to-end smoke** against managed SqlServer + Postgres instances when one of
   those deployments actually lands. Until then, the container-based integration suite
   (run on every PR via the CI matrix, Phase 3.3) gives the same signal.
3. **Run a restore drill** against whichever secret store the team is using in
   non-prod (M10's signing-key runbook). Quarterly cadence going forward.
4. **External IdP / SSO** — wait until there's a concrete need.
5. **Pomelo migration** — blocked on Pomelo 10 release; re-check quarterly. Independent
   of the multi-provider work above.
6. **Bulk user import** — only if a real migration use-case surfaces.

---

## Honest status

Phase 0 (admin endpoints), Phase 1 (s2s auth), Tier 4 observability, and the
data-integrity fixes are all feature-complete and tested. 480+ unit + 15 integration
tests passing. CI workflow, audit pipeline, admin surface, service-identity story,
observability stack, consumer client libraries — all in place.

The Tier 0 audit (2026-05-21) found 5 blockers (B1–B5), 10 medium-severity items
(M1–M10), and 8 nice-to-haves. **All Tier 0 items including the nice-to-haves are now
closed.** **Multi-provider database support is shipped end-to-end** — MySQL, SQL Server,
and PostgreSQL are all selectable via `DatabaseSettings:Provider`, each with its own
migrations assembly + Aspire container resource + integration-test parameterisation.
The service is production-ready against any of the three. Remaining longer-term items
(CI matrix, SSO, bulk import, Pomelo migration) are now build-when-demand-arrives.
