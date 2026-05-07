# Corporate-readiness TODO

Active findings only — closed items have been removed. Each entry carries the file/line so
it can be picked up cold. Tiered by impact for an enterprise, multi-replica, shared-by-many-apps
deployment; pick from the top and work down.

---

## Tier 1 — Correctness and multi-replica blockers

These are real bugs or operational issues that will manifest under load with multiple
replicas. Highest leverage for "production gate review with a straight face."







---

## Tier 2 — Security review prep

Things a corporate-security review would flag. Individually small, collectively the
difference between "polished" and "rough."


---

## Tier 3 — Code smells and known gaps

- [ ] **`User.WaitingForMfa` is a persisted boolean.**
  [User.cs:20](AuthenticationService/Entities/User.cs:20). Storing "is this user
  mid-MFA-challenge" on the User entity is the wrong shape — it's *session* state, not
  user state. Two browsers starting MFA simultaneously can't both succeed; the flag
  persists across replica restarts even when no challenge is outstanding.
  **Fix:** Drop it. Replace with a short-lived signed cookie / state token, or derive
  "in MFA" from a fresh-issued MFA token in Identity's `UserToken` store.

- [ ] **Residual fields on `User` entity.**
  [User.cs:25-40](AuthenticationService/Entities/User.cs:25). `MothersMaidenName`,
  `AddressLine1-3`, `Postcode`, `City` exist with no flow using them — leftovers from the
  deleted recovery flow. Plus the `// TODO: Update user details endpoint /nb` in
  AccountController hints at intent.
  **Fix:** Either build a profile-update endpoint that uses them, or drop the fields and
  add a column-drop migration. One or the other; current state is worst-of-both.

- [ ] **`JwtSecurityTokenHandler` instantiated per call.**
  [JWTService.cs](AuthenticationService/Services/JWTService.cs) — multiple sites.
  `new JwtSecurityTokenHandler()` created on every token operation. Lightweight but
  unnecessary allocation.
  **Fix:** `private static readonly JwtSecurityTokenHandler _handler = new();`. Thread-safe
  for the operations we use.

- [ ] **`EmailSubjects` has three near-identical lock subjects.**
  [EmailSubjects.cs:9-11](AuthenticationService/Constants/EmailSubjects.cs:9). `AccountLocked`
  is unused; `LockedAccountInfo` is for failed-login lockout; `SuspiciousActivity` is for
  refresh-reuse + threshold-escalation. Either rationalise to two (or one) or document
  the distinction.

- [ ] **`JWTSettings.ExpiryInMinutes` is `double`.**
  [JWTSettings.cs](AuthenticationService/Settings/JWTSettings.cs). `double` reads as
  "fractional minutes are meaningful" which they aren't. Either `int` (conventional) or
  `TimeSpan` (clearest). Cosmetic.

- [ ] **`AddAutoMapper(cfg => { }, typeof(Program))`.**
  [HostExtensions.cs:35](AuthenticationService/Extensions/HostExtensions.cs:35). Empty
  config delegate is a smell. If `RegistrationDto → User` is the only mapping (worth
  checking), hand-rolling is clearer and faster. AutoMapper's own current guidance is
  "use it where you have many mappings; hand-roll for one or two."

- [ ] **No HTTP request size limit.**
  Kestrel default is 30 MB. For an auth service that takes only small JSON bodies, this
  is overkill and a small DoS surface.
  **Fix:** Configure `KestrelServerOptions.Limits.MaxRequestBodySize` to something sane
  (1 MB).

---

## Tier 4 — Tests, observability, infrastructure

- [ ] **No tests, no CI.**
  No `*Test*.csproj`, no GitHub Actions / Azure Pipelines yaml. At minimum:
  - Unit tests for `JWTService` (claim shape, expiry, validation, rotation, reuse
    detection), `EcdsaKeyProvider`, the validators, the threshold-escalation worker logic.
  - Integration tests for the auth flow against a real MySQL container (Testcontainers).
  - Snapshot test for the JWKS / OIDC discovery doc shape.
  - CI workflow that runs `dotnet build` + tests on PR.

  Best done after Tier 1 lands so tests target a stable, correctness-improved surface.

- [ ] **No OpenTelemetry / W3C trace propagation.**
  Auth is the most-logged-against service. Add `services.AddOpenTelemetry()` with
  ASP.NET Core + EF Core + HttpClient instrumentation; export to whatever the platform's
  collector is (OTLP). Pairs with the missing-metrics gap below — OTel covers both traces
  and metrics in the same package.

- [ ] **No metrics emitted.**
  Logs aren't metrics. For Prometheus / OTLP-style operational dashboards you want
  counters / histograms for login-success rate, MFA adoption, refresh frequency, lockout
  rate, threshold-escalation fires. Lights up automatically when OpenTelemetry lands —
  framework-level metrics for ASP.NET Core / EF Core / HttpClient are built in. Custom
  business-metrics (e.g. "MFA-enabled user count") would need explicit `Meter` / `Counter`
  calls.

---

## Tier 5 — Missing features for enterprise multi-tenant use

These are likely real platform requirements once "shared by several apps" becomes more
than aspirational. None are blockers today; flagged so the design space is visible.

- [ ] **No service-to-service auth flow (client-credentials grant).**
  Currently consumers forward the user's JWT for downstream calls. Wrong because (a)
  audit logs show the user not the calling service, (b) services need to call when no
  user is involved (cron jobs, message handlers).
  **Standard answer:** client-credentials flow — each service has a `client_id` /
  `client_secret`, exchanges them for a service-identity JWT with its own claims and
  audience. Multi-day piece of work.

- [ ] **No admin operational endpoints.**
  Operational must-haves for an enterprise auth service:
  - List users
  - View / modify user details
  - Manually lock / unlock specific user
  - Revoke a user's sessions
  - Reset their MFA
  - Force password reset
  - View audit trail for a specific user
  
  Currently none exist. Either build them as `[Authorize(Policy="AdminOnly")]` admin
  endpoints, or document that ops will go via direct DB access (acceptable but
  unprofessional for a corporate platform).

- [ ] **No external IdP integration (SSO).**
  Many corporate apps want "log in with Microsoft / Google / Entra ID." Not in scope
  today but a likely requirement once the platform matures. Design considerations: claim
  mapping, account linking (existing local + new SSO), lifecycle (what happens when SSO
  removes a user upstream).

- [ ] **No bulk user import.**
  Onboarding to a corporate platform with existing users elsewhere — there's no migration
  path. Not initial scope but flagged.

- [ ] **No backup / disaster-recovery story for signing keys.**
  The PEM keys in `PrivateKeyDirectory` *are* the contract. If they're lost, every issued
  token becomes invalid AND we can't issue new ones until new keys are provisioned AND
  cached JWKS at every consumer needs to refresh.
  **Fix:** Document the runbook — how to back up via the chosen secret-store mechanism,
  how to restore, how often to test restore, what to do if all replicas of all keys are
  lost simultaneously (full re-auth event for every user).

- [ ] **No `OPERATIONS.md` / runbook.**
  New ops person joining the team has nothing to read. Should cover: how to deploy, how
  to rotate keys, how to debug a user-reported lockout, how to read SIEM dashboards, how
  to issue an ad-hoc password reset for a user, how to interpret threshold-escalation
  events.

---

## Tier 6 — Small corrections

- [ ] **`RuntimeDbSeed` doesn't handle DB unavailable at startup gracefully.** Would
  crash the replica with an opaque error. Either retry-with-backoff, or log clearly and
  fail fast so K8s reschedules.

- [ ] **`WellKnownController.Jwks` allocates new anonymous objects on every call.** Could
  be cached on `IEcdsaKeyProvider` since keys don't change at runtime (or invalidate on
  the next loader refresh, which doesn't currently exist anyway).


- [ ] **No `appsettings.Production.json` template.** Operators have nothing to copy/paste
  from. A template with placeholder values + comments explaining what each setting needs
  in production would shorten the bootstrap.

- [ ] **JWKS / discovery endpoints share the global rate-limit partition.** During a key
  rotation, many consumers fetching JWKS through the same outbound IP (corporate NAT)
  could trip the 4/10s default. Worth a more generous policy on `/.well-known/*`.


---

## Recommended next-up order

1. **Tier 1 items 1-5** (~1-2 days) — real correctness / multi-replica issues. Highest
   leverage. Refresh-token race fix is probably the single highest-value item.
2. **Tier 1 item 6** (email queueing, ~half-day) — operationally important under load.
3. **Tier 2 items 1, 3** (Swagger gating, SMTP password — ~1 hour) — small but
   visible-to-security wins.
4. **Tier 4 item 1: tests + CI.** Now you're testing a stable, correctness-improved
   surface — coverage you write during/after Tier 1 catches the regressions you'd
   otherwise re-introduce.
5. **Tier 4 items 2-3 (OpenTelemetry + metrics)** — half-day, lights up dashboards.
6. **Remaining Tier 2** as you go — individually small.
7. **Tier 5** items as real platform requirements arrive — don't pre-build.
8. **Tier 3 + 6** opportunistically alongside the above.

Rough effort estimate to reach "I'd put this in a production gate review with a straight
face": ~2 weeks of focused work for Tiers 1+2+4, plus whatever piece of Tier 5 arrives.
