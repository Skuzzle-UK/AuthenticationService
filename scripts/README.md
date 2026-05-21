# scripts/

Helper scripts for local dev. Not used in production.

| Script | What it does |
|---|---|
| `setup-local-backstage.ps1` (Windows) / `setup-local-backstage.sh` (mac/linux) | One-time setup that scaffolds a Backstage app under `local-backstage/`, applies our overlay config, and builds a Docker image so the Aspire AppHost can launch it via `--with-backstage`. See [`docs/operations/local-backstage.md`](../docs/operations/local-backstage.md). |
| `regen-openapi.ps1` / `regen-openapi.sh` | Regenerates `docs/api/openapi.json` from the auth service's Swashbuckle config. Runs `dotnet swagger tofile` (no server start required). The file is referenced from `catalog-info.yaml` via `$text:` so Backstage's REST API entity gets every endpoint with full request/response schemas. Auto-regenerated on every push to main by [`.github/workflows/regen-openapi.yml`](../.github/workflows/regen-openapi.yml); run manually when you want to refresh the spec on a feature branch before opening a PR. |

Run them from the repo root:

```powershell
# Windows
./scripts/setup-local-backstage.ps1
./scripts/regen-openapi.ps1
```

```bash
# mac / linux
./scripts/setup-local-backstage.sh
./scripts/regen-openapi.sh
```
