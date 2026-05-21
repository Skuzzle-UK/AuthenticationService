# Local Backstage via Aspire

How to bring up a Backstage instance locally that renders this repo's `catalog-info.yaml` + `docs/` (TechDocs), driven by the Aspire AppHost. **One-time setup script + F5** once it's done.

> If you already have a Backstage instance running somewhere (your team's prod / staging Backstage), you don't need any of this — just register this repo's URL in Backstage's catalog and `catalog-info.yaml` will be picked up automatically. The local setup below is for developers who are working on this repo *without* an existing Backstage to point at.

## Prereqs

- **Node 20 or later** (`node --version` — Backstage refuses to start on Node 18 or earlier)
- **corepack** (ships with Node 16.10+; the script enables it if needed — picks up Backstage's required yarn version automatically)
- **Docker Desktop** (or Rancher / Podman Desktop) — Aspire uses it to run the container
- **~10 minutes + ~500MB disk** for the first-time setup. Subsequent rebuilds (e.g. after editing the overlay config) take ~2 min.

## One-time setup

From the repo root:

```powershell
# Windows
./scripts/setup-local-backstage.ps1
```

```bash
# mac / linux
./scripts/setup-local-backstage.sh
```

What the script does, step by step:

1. **Scaffolds Backstage** under `local-backstage/` via `npx @backstage/create-app@latest`. This is the official Backstage create-app tool — same one a fresh team would run to start a new Backstage instance.
2. **Copies our overlay** (`AuthenticationService.AppHost/backstage/app-config.local.yaml`) into the scaffolded app. Backstage auto-merges `*.local.yaml` on top of its baseline `app-config.yaml`, so this overrides only the keys we care about (catalog source, TechDocs builder, SQLite DB, guest auth).
3. **`yarn install` + `yarn tsc` + `yarn build:backend`** to produce a built Backstage backend.
4. **`docker image build`** to package the built backend into an image tagged `authentication-service-backstage:local` — exactly what `AppHost.cs` references.

After the script completes successfully:

```
─────────────────────────────────────────────────────────────
  Done. Image 'authentication-service-backstage:local' built and tagged.
  ...
─────────────────────────────────────────────────────────────
```

## Running

**In Visual Studio:** pick the **`https-with-backstage`** launch profile from the dropdown next to the Start button, then F5. (The default `https` profile stays Backstage-free so plain F5 doesn't need the image built.)

**From the command line:**

```bash
dotnet run --project AuthenticationService.AppHost --launch-profile https-with-backstage
```

…or pass the flag manually if you prefer a one-off:

```bash
dotnet run --project AuthenticationService.AppHost -- --with-backstage
```

Once the Aspire dashboard shows the `backstage` resource as **Running** (typically ~10-30s after start — Backstage takes a moment to scan the catalog), open `http://localhost:7007`.

You'll see:

- **Catalog tab** lists the `authentication` System and its four Components: `authentication-service`, `authentication-service-tokenvalidationlib`, `authentication-service-tokenclientlib`, `example-consumer`.
- **Docs tab** (on the `authentication-service` Component) renders the full `docs/` tree as TechDocs — searchable, navigable, with the left-side nav from `mkdocs.yml`.
- **APIs tab** lists the REST + OIDC API entities declared in `catalog-info.yaml`.

Default F5 (without `--with-backstage`) doesn't touch Backstage — startup is unchanged.

## When to re-run the setup script

| Change | Action |
|---|---|
| Edit `docs/**/*.md` | Nothing — docs are mounted into the container at runtime. Hit refresh in Backstage. |
| Edit `catalog-info.yaml` | Nothing — also mounted at runtime. Backstage rescans on a short interval. |
| Edit `AuthenticationService.AppHost/backstage/app-config.local.yaml` | Re-run the setup script. The overlay is baked into the docker image, so the image needs rebuilding. |
| Update Backstage to a newer release | Delete `local-backstage/`, then re-run the setup script. `create-app` will pull the latest. |

## What the AppHost wires up

Under `if (withBackstage) { ... }` in `AuthenticationService.AppHost/AppHost.cs`:

| Mount | Source (host) | Destination (container) | Why |
|---|---|---|---|
| Repo root, read-only | `<repo root>` | `/repo` | So `/repo/catalog-info.yaml` resolves (the overlay points `catalog.locations` at this path) and Backstage can `mkdocs build` against `/repo/docs/` for TechDocs. |

| Port | Inside container | On host |
|---|---|---|
| 7007 | Backstage backend serves the UI + API | `http://localhost:7007` |

The overlay app-config is **not** mounted at runtime — it's baked into the image by the setup script at build time. Folder-mount only (not single-file) sidesteps Docker Desktop on Windows's known rejection of single-file bind mounts.

## What's in the overlay config

`AuthenticationService.AppHost/backstage/app-config.local.yaml` overrides four things on top of `create-app`'s baseline:

- **`backend.database`** → SQLite in-memory. No separate Postgres container needed for local previews. State resets on every AppHost restart — fine for "demo + iterate" but if you accumulate scaffold history or TODO entries you'd want to swap to Postgres.
- **`catalog.locations`** → points at `/repo/catalog-info.yaml`, the file the AppHost mounted via the repo bind.
- **`techdocs.builder`** = `local`, **`techdocs.generator.runIn`** = `local`. Backstage runs `mkdocs build` inside the container on demand against `/repo/docs/`. (Backstage's default create-app template ships with the `techdocs-core` Python package installed in the image.)
- **`auth.providers.guest`** → guest mode. Anyone hitting `http://localhost:7007` is logged in as `guest@local`. Safe because the container binds to localhost only; real Backstage deployments wire OIDC / GitHub Apps / SAML here.

## Troubleshooting

**Setup script: `node --version` is too low.** Upgrade Node to 20+ via [https://nodejs.org](https://nodejs.org) (LTS is fine). On Windows with multiple Node installs, `nvm-windows` or `volta` can switch between versions.

**Setup script: `yarn install` fails with a checksum error.** Delete `local-backstage/` and re-run the script. Usually a partial download from a previous failed run.

**Setup script: `docker image build` hangs at "Sending build context."** Docker is doing a big transfer (~500MB). Usually completes in 30-60s.

**Aspire dashboard: `backstage` resource fails with "image not found."** Run `./scripts/setup-local-backstage.ps1` (or `.sh`) — the image needs to be built before Aspire can launch it. `docker image ls authentication-service-backstage:local` confirms whether the image exists.

**Aspire dashboard: `backstage` container starts then exits.** Open the resource's logs in the dashboard. Almost always a YAML error in our overlay. Re-validate `AuthenticationService.AppHost/backstage/app-config.local.yaml` against a YAML linter, then re-run the setup script.

**Backstage UI loads but no docs appear under the Docs tab.** The `mkdocs build` step inside the container probably failed. Open the `backstage` container logs in the Aspire dashboard — most often this is a missing markdown extension or a syntax issue. Try `pip install mkdocs mkdocs-material mkdocs-techdocs-core && mkdocs build` locally against this repo to reproduce.

**Catalog tab is empty.** The repo bind-mount didn't resolve to the expected path. Check `local-backstage` isn't somehow symlinked elsewhere, and that the `repoRoot` calculation in `AppHost.cs` matches your layout (the calc walks up out of `AuthenticationService.AppHost/bin/Debug/<tfm>/` — should land at the repo root containing `AuthenticationService.sln`).

**Backstage container can't reach `/repo/catalog-info.yaml`.** Make sure Docker Desktop has filesystem sharing enabled for the drive your repo lives on (Settings → Resources → File sharing).

## Upgrading

Bump Backstage by deleting `local-backstage/` and re-running the setup script — `create-app@latest` pulls the most recent stable Backstage. Verify the catalog + docs still render before committing any overlay-config tweaks the new Backstage version might need.

## Why is `local-backstage/` not in git?

It's ~500MB after a fresh install (Backstage's `node_modules` + the built backend bundle), it's regenerable from the script + the overlay we *do* commit, and Backstage version-bumps would create huge diffs. The source-of-truth lives at `AuthenticationService.AppHost/backstage/app-config.local.yaml` (committed) and `scripts/setup-local-backstage.*` (committed). The scaffolded app is build output.

## When to upgrade beyond local-only Backstage

The local setup is for "see what the catalog looks like" / "validate `catalog-info.yaml` changes before pushing." For an actually-shared Backstage instance you'd want:

- **Postgres-backed catalog** so state survives restarts (TODOs, scaffold history, manually-added catalog entries).
- **Real auth provider** (OIDC against your IdP, GitHub Apps, SAML).
- **Hosted TechDocs** — pre-built docs uploaded to S3/GCS/Azure rather than built per-request. See [Backstage TechDocs deployment](https://backstage.io/docs/features/techdocs/configuration).
- **Plugin curation** — which scaffolder templates, which lifecycle plugins, which integrations.

All of those are deployment decisions outside this repo. The local-Backstage setup is just enough to validate that **this** repo's catalog + docs render correctly before you push them to your team's real Backstage.

## See also

- [`catalog-info.yaml`](../../catalog-info.yaml) — the entity declarations Backstage ingests
- [`mkdocs.yml`](../../mkdocs.yml) — TechDocs build config
- [`AuthenticationService.AppHost/backstage/`](../../AuthenticationService.AppHost/backstage/) — overlay app-config (source of truth, copied into the scaffolded app by the script)
- [`scripts/setup-local-backstage.ps1`](../../scripts/setup-local-backstage.ps1) / [`.sh`](../../scripts/setup-local-backstage.sh) — the setup script itself
- Upstream Backstage docs: [https://backstage.io/docs](https://backstage.io/docs)
