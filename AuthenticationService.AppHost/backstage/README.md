# Backstage local-dev assets

Source-of-truth files that customise the locally-running Backstage instance. See [`docs/operations/local-backstage.md`](../../docs/operations/local-backstage.md) for the full setup walk-through.

| File | What | Copied to (inside `local-backstage/`) |
|---|---|---|
| `app-config.local.yaml` | Backstage overlay config. Backstage auto-merges `*.local.yaml` on top of its baseline `app-config.yaml`. Overrides four things: catalog source (`/repo/catalog-info.yaml`), TechDocs builder (local), DB (in-memory SQLite), auth (guest mode). | `app-config.local.yaml` |
| `Dockerfile` | Custom multi-stage Dockerfile. Replaces create-app's default — does the whole build (yarn install + tsc + build:backend) **inside the container** so the host doesn't need Python 3 + Visual Studio C++ Build Tools to compile Backstage's native modules (better-sqlite3, isolated-vm, cpu-features). | `packages/backend/Dockerfile` |

Both are copied into the scaffolded Backstage app by `scripts/setup-local-backstage.{ps1,sh}` during step 2, then `docker image build` packages everything into `authentication-service-backstage:local`.

This folder is **build-input only** — the docker image is the actual output the Aspire AppHost references. To pick up changes to either file, re-run the setup script so the image is rebuilt.

The `local-backstage/` folder (created by the setup script) holds the actual scaffolded Backstage app and is git-ignored — it's regenerable from these files + the script.

Production Backstage deployments don't use these files. The platform team's Backstage has its own app-config that registers this repo by URL.
