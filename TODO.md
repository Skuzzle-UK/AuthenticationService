# Corporate-readiness TODO

What's still outstanding. Closed items have been removed — they're in git history; this
doc is forward-looking. Tiered by impact for an enterprise, multi-replica, shared-by-many-apps
deployment; pick from the top and work down.

> **Status as of 2026-05-21:** all Tier 0 blockers (B1–B5), all 10 medium-priority items
> (M1–M10), and all 8 nice-to-haves are closed. The service is production-ready. Only
> long-running deferred items remain (Pomelo migration blocked on Pomelo 10; SSO and
> bulk-import flagged for "build when demand arrives").

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

- [ ] **Operational runbook still has TBDs.** `docs/operations/runbook.md` was scaffolded as a skeleton; the obvious gaps were filled in via B5 (admin recovery), M8 (broken cross-ref), and M9 (lock-account procedure). Remaining placeholders (lines ~90–97) are reasonable "fill in as the team actually operates the service" items rather than authoring-time blocks.

---

## Recommended next-up order

1. **Run a restore drill** against whichever secret store the team is using in
   non-prod. The point of M10's universal runbook is that it'll guide one regardless of
   choice — a drill in staging proves it. Quarterly cadence going forward.
2. **External IdP / SSO** — wait until there's a concrete need (which provider, what
   claim mapping, what account-linking semantics).
3. **Pomelo migration** — blocked on Pomelo 10 release; re-check quarterly.
4. **Bulk user import** — only if a real migration use-case surfaces.

---

## Honest status

Phase 0 (admin endpoints), Phase 1 (s2s auth), Tier 4 observability, and the
data-integrity fixes are all feature-complete and tested. 480+ unit + 15 integration
tests passing. CI workflow, audit pipeline, admin surface, service-identity story,
observability stack, consumer client libraries — all in place.

The Tier 0 audit (2026-05-21) found 5 blockers (B1–B5), 10 medium-severity items
(M1–M10), and 8 nice-to-haves. **All Tier 0 items including the nice-to-haves are now
closed.** The service is production-ready. Remaining roadmap items (SSO, bulk import,
Pomelo migration) are all "build when demand arrives."
