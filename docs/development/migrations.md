# Database migrations

The auth service supports three database providers — **MySQL, SQL Server, and
PostgreSQL** — picked at startup via `DatabaseSettings:Provider`. EF Core requires
**one model snapshot per provider per DbContext**, so each provider's migrations live
in their own assembly. Adding a migration after a model change therefore means running
the EF CLI **once per active provider**.

> If you've only worked with single-provider EF projects before, the "snapshot per
> provider" constraint is the surprise. Everything else looks normal.

---

## Project layout

| Provider | Migrations assembly | Where the files live |
|---|---|---|
| MySQL (Oracle) | `AuthenticationService.Migrations.MySql` | `AuthenticationService.Migrations.MySql/Migrations/` |
| SQL Server | `AuthenticationService.Migrations.SqlServer` | `AuthenticationService.Migrations.SqlServer/Migrations/` |
| PostgreSQL | `AuthenticationService.Migrations.Postgres` | `AuthenticationService.Migrations.Postgres/Migrations/` |

Each provider's migrations assembly contains:

- `<timestamp>_<Name>.cs` — the `Migration` subclass with `Up()` + `Down()`.
- `<timestamp>_<Name>.Designer.cs` — EF-generated metadata.
- `DatabaseContextModelSnapshot.cs` — the cumulative model snapshot for this provider.

All three providers follow the same layout — each migrations assembly carries its own
`DesignTimeFactory` (so the EF CLI can target the project directly without booting the
full host pipeline) and an MSBuild `AfterTargets="Build"` step that copies the DLL into
the main project's `bin/` folder. At runtime, an `AssemblyLoadContext.Resolving` hook in
`Program.cs` falls back to disk-probing for any `AuthenticationService.Migrations.*`
assembly so the missing `deps.json` entry doesn't break `EF.MigrationsAssembly(...)`'s
`Assembly.Load`.

---

## Adding a migration after a model change

When you change anything in `DatabaseContext.OnModelCreating`, an entity class, or
anywhere the model is computed from, you need to add a migration to **every active
provider** so all deployments can apply the schema change.

### MySQL

```bash
dotnet ef migrations add <DescriptiveName> \
  --project AuthenticationService.Migrations.MySql \
  --startup-project AuthenticationService.Migrations.MySql \
  --context DatabaseContext \
  --output-dir Migrations
```

Files land in `AuthenticationService.Migrations.MySql/Migrations/`.

### SQL Server

```bash
dotnet ef migrations add <DescriptiveName> \
  --project AuthenticationService.Migrations.SqlServer \
  --startup-project AuthenticationService.Migrations.SqlServer \
  --context DatabaseContext \
  --output-dir Migrations
```

Files land in `AuthenticationService.Migrations.SqlServer/Migrations/`.

### PostgreSQL

```bash
dotnet ef migrations add <DescriptiveName> \
  --project AuthenticationService.Migrations.Postgres \
  --startup-project AuthenticationService.Migrations.Postgres \
  --context DatabaseContext \
  --output-dir Migrations
```

Files land in `AuthenticationService.Migrations.Postgres/Migrations/`.

> **Why `--startup-project` is the migrations project itself, not the main
> AuthenticationService:** the migrations project has its own `DesignTimeFactory` that
> wires the provider directly. Using the main project as the startup would pick up
> `DatabaseSettings:Provider` from config (which is MySQL by default) — wrong
> provider, wrong snapshot, very confusing failure.

### Same `<DescriptiveName>` across providers?

Yes. Use the same name for the same logical change. The timestamps will differ (each
`dotnet ef migrations add` invocation captures the wall clock at that moment), but the
migration's **name** is what humans read in PR diffs.

```
AuthenticationService/Migrations/20260601090000_AddUserPreferredLocale.cs
AuthenticationService.Migrations.SqlServer/Migrations/20260601090030_AddUserPreferredLocale.cs
AuthenticationService.Migrations.Postgres/Migrations/20260601090045_AddUserPreferredLocale.cs
```

---

## What happens if you forget one provider

Best case: the deployment using that provider can't apply the migration. The pod
fails to start with an EF Core error along the lines of "no migration found in
assembly for model state Y." The orchestrator restarts the pod, fails again,
eventually pages.

Worst case: someone manually skips migrations (e.g. they set
`RunMigrationsAtStartup=false`) and the schema drifts. Then runtime queries against
columns that don't exist throw on first request.

**Prevention:** if you change the model, do both `dotnet ef migrations add` runs in
the same commit. Add a CI check eventually (Phase 2.1 follow-up) that diffs the two
provider snapshots' models and fails the build if they're out of sync.

---

## Dev-loop: running the app against a non-MySQL provider

The Aspire AppHost takes a provider switch — pass `--db-provider=<name>` to
`dotnet run`, or set the `INTEGRATION_DB_PROVIDER` env var. The AppHost then spins up
the matching container (MySQL, SQL Server, or PostgreSQL) and wires
`DatabaseSettings__Provider` + the right `ConnectionStrings__<Provider>` env var into
the auth resource.

```bash
# SQL Server local dev
dotnet run --project AuthenticationService.AppHost -- --db-provider=SqlServer

# PostgreSQL local dev
dotnet run --project AuthenticationService.AppHost -- --db-provider=PostgreSQL
```

PowerShell:

```powershell
dotnet run --project AuthenticationService.AppHost -- --db-provider=PostgreSQL
```

Useful when you're adding a migration to a non-default provider and want to actually
exercise it. Same flag drives `dotnet test` against the integration suite — see
[development/testing.md](testing.md#running-against-a-non-mysql-database).

---

## How migrations get applied at runtime

`AuthenticationService/Extensions/WebApplicationExtensions.cs` calls
`app.RunMigrations()` during `ConfigureApplicationAsync` if `RunMigrationsAtStartup`
is `true` (the default). That method internally calls `dbContext.Database.Migrate()`,
which:

1. Reads the `__EFMigrationsHistory` table to see what's already been applied.
2. Compares against the migrations in the configured `MigrationsAssembly`.
3. Applies anything new, in timestamp order.

The `MigrationsAssembly` is picked in `HostExtensions.AddDatabase`'s switch on
`DatabaseSettings:Provider`. For MySQL it defaults to the main assembly; for SQL
Server it's set explicitly to `AuthenticationService.Migrations.SqlServer`; for
PostgreSQL, `AuthenticationService.Migrations.Postgres`.

### Disabling startup migrations

Set `RunMigrationsAtStartup=false` in the deployment's config to skip
`Database.Migrate()` on boot. Use this when:

- The deploy pipeline applies migrations as a separate step (recommended for
  multi-replica deployments — only one replica should migrate, the rest just connect
  to the already-migrated schema).
- You want to inspect the migration SQL before applying it. Generate the SQL with
  `dotnet ef migrations script <FromMigration> <ToMigration>`.

---

## Common scenarios

### Generated a bad migration, want to undo

If you haven't deployed it yet:

```bash
# MySQL
dotnet ef migrations remove --project AuthenticationService --startup-project AuthenticationService

# SQL Server
dotnet ef migrations remove --project AuthenticationService.Migrations.SqlServer --startup-project AuthenticationService.Migrations.SqlServer
```

This deletes the most recent migration files **only if** they haven't been applied
to a database. If they have, you need `dotnet ef database update <PreviousMigration>`
first to roll the DB back, then `migrations remove`.

### Dev DB is in a weird state, want to nuke and reseed

```bash
# Drop everything
dotnet ef database drop --project AuthenticationService --startup-project AuthenticationService

# Recreate
dotnet ef database update --project AuthenticationService --startup-project AuthenticationService
```

Or just bin the Docker / Aspire container and let `Database.EnsureCreated` recreate
from migrations on next `dotnet run`.

### Inspect what SQL would be generated

```bash
dotnet ef migrations script <FromMigration> <ToMigration> \
  --project AuthenticationService.Migrations.SqlServer \
  --startup-project AuthenticationService.Migrations.SqlServer \
  --output migration.sql
```

Useful for the "deploy pipeline applies migrations as a separate step" pattern above.

---

## Why the SqlServer + Postgres migrations DLLs end up in the main project's bin folder

When `Database:Provider=SqlServer` or `=PostgreSQL` is configured, EF Core at runtime
calls `Assembly.Load("AuthenticationService.Migrations.SqlServer")` or `…Postgres` to
find the migrations. That probes the main project's bin folder.

Normally you'd solve this by having the main project ProjectReference the migrations
projects — but each migrations project already ProjectReferences the main project (for
`DatabaseContext`). A reverse reference would create a build cycle.

The fix is an `AfterTargets="Build"` MSBuild target in each migrations project's
`.csproj` that copies its output DLL into the main project's
`bin/<Configuration>/<TargetFramework>/` folder after every build. Works for
`dotnet build`, `dotnet run`, and `dotnet publish`.

---

## Cross-references

- [`deployment.md`](../operations/deployment.md) — runtime side: provider config,
  connection strings, `RunMigrationsAtStartup`.
- [`reference/configuration.md`](../reference/configuration.md) — `DatabaseSettings`
  + connection-string config.
- TODO.md "Planned engineering — multi-provider database support" — the rolling plan
  for adding more providers.
- `AuthenticationService/Extensions/HostExtensions.cs` — `AddDatabase` switch on
  `Provider`.
- `AuthenticationService/Storage/DatabaseContext.cs` — the model. Anything you
  change here needs migrations across every active provider.
