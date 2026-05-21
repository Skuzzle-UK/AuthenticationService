# Testing

Five test projects, **541 unit tests** total + **15 integration tests**. Two layers — fast unit feedback for everyday work, slower integration tests for the cross-cutting / DB-shape stuff.

## Layout

| Project | Type | Tests | Duration | When |
|---|---|---|---|---|
| `Tests/AuthenticationService.TokenValidationLib.Tests` | Unit | 10 | ~0.2s | Every commit |
| `Tests/AuthenticationService.TokenClientLib.Tests` | Unit | 38 | ~1s | Every commit |
| `Tests/AuthenticationService.Shared.Tests` | Unit | 78 | ~0.1s | Every commit |
| `Tests/AuthenticationService.Tests` | Unit | 415 | ~3s | Every commit |
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
