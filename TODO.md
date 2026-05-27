# Corporate-readiness TODO

What's still outstanding. Closed items have been removed — they're in git history; this
doc is forward-looking. Tiered by impact for an enterprise, multi-replica, shared-by-many-apps
deployment; pick from the top and work down.

> **Status as of 2026-05-21:** all Tier 0 blockers (B1–B5), all 10 medium-priority items
> (M1–M10), and all 8 nice-to-haves are closed. The service is production-ready against
> MySQL. **Multi-provider DB Phase 1 (provider-selection seam) shipped.** Phase 2
> (SQL Server) and Phase 3 (PostgreSQL) are the next active work items.

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

### Phase 2 — Add SQL Server

- [ ] **Add `Microsoft.EntityFrameworkCore.SqlServer` package** (10.0.x).
- [ ] **Set up a per-provider migrations folder.** Create `Migrations.SqlServer/`, add
      a design-time factory or env-var switch so `dotnet ef migrations add` against
      `--provider sql-server` lands the right SQL into the right folder. Configure
      `b.MigrationsAssembly("AuthenticationService")` + per-provider folder selection
      in `AddDatabase`.
- [ ] **Generate the initial migration** against a real SQL Server (Aspire-spun container
      or a local instance). `dotnet ef migrations add Initial --context DatabaseContext
      --output-dir Migrations.SqlServer`.
- [ ] **Validator update:** add `SqlServer` to the allowed `Provider` values.
- [ ] **`ConnectionStrings:SqlServer`** documented + plumbed; pulled by the `SqlServer`
      branch in `AddDatabase`.
- [ ] **Built-in retry strategy** via `opt.UseSqlServer(connStr, sql => sql.EnableRetryOnFailure(5, TimeSpan.FromSeconds(30), errorNumbersToAdd: null))`
      — matches the MySQL retry budget (5 × 30s).
- [ ] **Aspire AppHost** optional `AddSqlServer()` resource, gated by a launch profile
      or env var so local dev can pick MySQL or SQL Server.
- [ ] **Integration tests:** parameterise `AppHostFixture` to choose the DB resource
      based on env var `INTEGRATION_DB_PROVIDER=SqlServer`. CI matrix runs the suite
      against MySQL by default; SQL Server matrix entry runs the same scenarios.
- [ ] **End-to-end smoke:** deploy with `Database:Provider=SqlServer` →
      `RunMigrationsAtStartup=true` → first request hits a freshly-created schema →
      login + JWKS round-trip succeeds.
- [ ] **Docs:** add SQL Server sections to `docs/operations/deployment.md`,
      `docs/reference/configuration.md`, and a new "supported providers" note in
      `docs/architecture.md`.

**Effort:** ~1 day.

### Phase 3 — Add PostgreSQL

Same shape as Phase 2 with the Npgsql provider.

- [ ] **`Npgsql.EntityFrameworkCore.PostgreSQL`** package (10.0.x).
- [ ] **`Migrations.Postgres/` folder** with initial migration generated against a real
      PostgreSQL instance (Aspire `AddPostgres()`).
- [ ] **Validator update:** add `PostgreSQL` to the allowed `Provider` values.
- [ ] **`ConnectionStrings:PostgreSQL`** documented + plumbed.
- [ ] **Built-in retry strategy** via `opt.UseNpgsql(connStr, npg => npg.EnableRetryOnFailure(5, TimeSpan.FromSeconds(30), errorCodesToAdd: null))`.
- [ ] **Npgsql gotchas to verify during this phase:**
  - `LegacyTimestampBehavior` AppContext switch — Npgsql 6+ defaults to strict
    `timestamp with time zone` handling. Confirm `DateTime` / `DateTimeOffset` columns
    round-trip cleanly; turn the switch on (or, better, fix any UTC-vs-local
    inconsistencies the strict mode surfaces).
  - Case-insensitive `NormalizedEmail` / `NormalizedUserName` lookups — Identity stores
    the upper-cased form already, so plain equality works on the normalised column. No
    `citext` extension needed unless we later add case-insensitive lookups against
    non-normalised columns.
  - Connection-pooling defaults differ from MySQL's — confirm `Maximum Pool Size` in
    the connection string is appropriate for the deployment.
- [ ] **Aspire AppHost** `AddPostgres()` resource alongside the MySQL / SQL Server ones.
- [ ] **Integration tests:** add `INTEGRATION_DB_PROVIDER=PostgreSQL` matrix entry.
- [ ] **End-to-end smoke + docs**, same shape as Phase 2.

**Effort:** ~1 day.

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

  Three Oracle-provider workarounds shipped with the integration-test debugging would all disappear under Pomelo:
  - `DateOnly` round-trip needs an explicit value converter against Oracle; Pomelo native.
  - `DateTimeOffset.MaxValue` overflows MySQL `DATETIME` via Oracle; Pomelo handles cleanly.
  - `Contains` on `List<string>` doesn't translate via Oracle (forced N+1 loop in
    threshold-escalation worker); Pomelo translates fine.

  Pomelo would also replace the custom `MySqlRetryingExecutionStrategy` (shipped for B1) with its native `EnableRetryOnFailure`.

  **Status:** latest Pomelo on nuget.org is `9.0.0`, which hard-pins to EF Core 9.0.x. We're on EF Core 10; downgrading would cascade into Identity / Aspire / hosting incompatibilities. Re-check quarterly; the migration is ~half a day once Pomelo 10 ships.

  **Workarounds in place until then:** `DateOnly` value converter in `DatabaseContext.OnModelCreating`, `LockoutDurations.Indefinite` sentinel constant, per-jti loop in `RevokedTokenReplayEscalationService.RunSweepAsync`, custom `MySqlRetryingExecutionStrategy`. Each carries a code comment explaining "this can revert when we move to Pomelo."

---

## Tier 5 — Missing features for enterprise multi-tenant use (build when demand arrives)

None of these block shipping. Flagged so the design space is visible.

- [ ] **External IdP integration (SSO).** Many corporate apps want "log in with Microsoft / Google / Entra ID." Not in scope today but a likely requirement once the platform matures. Design considerations: claim mapping, account linking (existing local + new SSO), lifecycle (what happens when SSO removes a user upstream).

- [ ] **Bulk user import.** Onboarding to a corporate platform with existing users elsewhere — there's no migration path. Not initial scope but flagged.

- [ ] **Operational runbook — three team-decision placeholders remain.** The runbook is now a working doc, not a skeleton. The decision tree, common procedures, and a full "I can't log in" triage table are filled in from code knowledge. Three placeholders stay because they need decisions the codebase can't make: **first-time prod deployment** (Helm / Terraform / Pulumi / kubectl flow — depends on platform choice), **SLO / SLA targets** (availability + latency commitments), and **incident-response procedure** (on-call rotation + paging tool + escalation matrix). Each one's expected shape is sketched in `runbook.md` so whoever fills them in knows what's expected.

---

## Recommended next-up order

1. **Multi-provider DB — Phase 2 (SQL Server).** ~1 day. Probably the higher-demand of
   the two; .NET shops default to SQL Server. Phase 1 (seam) is shipped — Phase 2 is
   now an incremental add.
2. **Multi-provider DB — Phase 3 (PostgreSQL).** ~1 day.
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
closed.** The service is production-ready **against MySQL**. Active engineering work:
**multi-provider database support** — three-phase plan above, ~2.5 days for MySQL +
SQL Server + PostgreSQL. Remaining longer-term items (SSO, bulk import, Pomelo
migration) are still "build when demand arrives."
